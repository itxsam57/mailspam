import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { normalizeImapFolder, providerFolderPath } from "../../server/src/adapters/imap/folderNames.js";
import { sameOrganizationalDomain } from "../../server/src/util/domainRelation.js";
import {
  hasDeterministicOfficialIdentity,
  identityImpersonationLayer,
  isDirectOfficialSenderDomain,
  isOfficialPrivateRelaySender,
} from "../../server/src/engine/layers/identityImpersonation.js";
import { messageIntentLayer } from "../../server/src/engine/layers/messageIntent.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { unsubscribeCapability } from "../../server/src/workflows/unsubscribe.js";

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  return {
    provider: "icloud",
    accountProof: "proof",
    messageId: "message-id",
    providerNativeId: "native-id",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Example", address: "news@example.com", domain: "example.com" },
    replyTo: null,
    subject: "Example message",
    date: new Date(0).toISOString(),
    authentication: { providerTrust: "trusted", spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview: "Readable newsletter content ".repeat(40),
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: "example.list", listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 1000, encoding: "plain", contentCoverage: "complete" },
    ...overrides,
  };
}

const threatFeed = { getVerifiedEntries: () => [] };
const deps = () => ({ personalPolicy: new InMemoryPersonalPolicyStore(), threatFeed });
const boundedNote = "Readable text was bounded to 24576 bytes.";

describe("IMAP inbox discovery", () => {
  it("recognizes uppercase INBOX even when specialUse is backslash-prefixed", () => {
    const folder = { path: "INBOX", name: "INBOX", specialUse: "\\Inbox" };
    expect(normalizeImapFolder(folder)).toBe("inbox");
    expect(providerFolderPath(folder)).toBe("INBOX");
  });

  it("uses the actual path when an unrelated special-use token is present", () => {
    expect(normalizeImapFolder({ path: "INBOX", specialUse: "\\All" })).toBe("inbox");
  });
});

describe("organizational domain identity", () => {
  it("treats legitimate subdomains as the same sender organization", () => {
    expect(sameOrganizationalDomain("service.tiktok.com", "tiktok.com")).toBe(true);
    expect(sameOrganizationalDomain("id.apple.com", "email.apple.com")).toBe(true);
    expect(sameOrganizationalDomain("email.sadapay.pk", "sadapay.pk")).toBe(true);
  });

  it("does not flag related reply-to subdomains", () => {
    const result = identityImpersonationLayer(envelope({
      from: { displayName: "TikTok", address: "newsletter@service.tiktok.com", domain: "service.tiktok.com" },
      replyTo: { displayName: null, address: "reply@tiktok.com", domain: "tiktok.com" },
    }));
    expect(result.evidence.some((item) => item.code === "REPLY_TO_MISMATCH")).toBe(false);
  });

  it("still flags unrelated reply-to domains", () => {
    const result = identityImpersonationLayer(envelope({
      from: { displayName: "Example", address: "news@example.com", domain: "example.com" },
      replyTo: { displayName: null, address: "reply@gmail.com", domain: "gmail.com" },
    }));
    expect(result.evidence.some((item) => item.code === "REPLY_TO_MISMATCH")).toBe(true);
  });

  it("recognizes direct official domains", () => {
    const apple = envelope({
      from: { displayName: "iCloud", address: "noreply@email.apple.com", domain: "email.apple.com" },
      subject: "Your iCloud storage is full",
    });
    expect(isDirectOfficialSenderDomain(apple)).toBe(true);
    expect(hasDeterministicOfficialIdentity(apple)).toBe(true);
  });

  it("recognizes an Apple private-relay address only when it encodes the claimed brand domain", () => {
    const foodpanda = envelope({
      from: {
        displayName: "foodpanda",
        address: "contact_at_info_foodpanda_pk_29xqmt77nd_a6dc6b02@privaterelay.appleid.com",
        domain: "privaterelay.appleid.com",
      },
      subject: "Craving something delicious?",
    });
    expect(isOfficialPrivateRelaySender(foodpanda)).toBe(true);
    expect(hasDeterministicOfficialIdentity(foodpanda)).toBe(true);

    const unrelatedAlias = envelope({
      from: {
        displayName: "foodpanda",
        address: "unrelated_alias_123@privaterelay.appleid.com",
        domain: "privaterelay.appleid.com",
      },
      subject: "Craving something delicious?",
    });
    expect(isOfficialPrivateRelaySender(unrelatedAlias)).toBe(false);
  });

  it("handles the one-letter X brand only as an exact display label", () => {
    const xMessage = envelope({
      from: { displayName: "X", address: "verify@x.com", domain: "x.com" },
      subject: "New login to X from an iPhone",
    });
    expect(hasDeterministicOfficialIdentity(xMessage)).toBe(true);
  });
});

describe("provider-neutral unsubscribe availability", () => {
  it("does not offer one-click from declaration alone without DKIM authorization", () => {
    const capability = unsubscribeCapability(envelope({
      listHeaders: {
        listId: "list.example",
        listUnsubscribe: "<mailto:leave@example.com>, <https://example.com/unsubscribe?id=1>",
        listUnsubscribePost: "List-Unsubscribe=One-Click",
      },
    }));
    expect(capability).toMatchObject({
      available: true,
      method: "mailto",
      target: "mailto:leave@example.com",
      source: "list_header",
    });
  });

  it("exposes ordinary header links instead of hiding them", () => {
    const capability = unsubscribeCapability(envelope({
      listHeaders: { listId: null, listUnsubscribe: "<https://example.com/preferences>", listUnsubscribePost: null },
    }));
    expect(capability).toMatchObject({ available: true, method: "link_only", source: "list_header" });
  });

  it("exposes mailto unsubscribe actions", () => {
    const capability = unsubscribeCapability(envelope({
      listHeaders: { listId: null, listUnsubscribe: "<mailto:remove@example.com?subject=unsubscribe>", listUnsubscribePost: null },
    }));
    expect(capability).toMatchObject({ available: true, method: "mailto", source: "list_header" });
  });

  it("finds explicit unsubscribe footer links when headers are absent", () => {
    const capability = unsubscribeCapability(envelope({
      listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
      links: [{
        visibleText: "Manage email preferences or unsubscribe",
        rawUrl: "https://example.com/unsubscribe/footer",
        normalizedUrl: "https://example.com/unsubscribe/footer",
        claimedBrand: null,
        brandDomainMismatch: null,
      }],
    }));
    expect(capability).toMatchObject({ available: true, method: "link_only", source: "message_footer" });
  });
});

describe("bounded inbox verdicts", () => {
  it("allows authenticated bounded newsletter content to resolve Safe", () => {
    const result = scanMessage(envelope({
      parseStatus: "partial",
      parseNotes: [boundedNote],
      diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 40000, encoding: "multipart", contentCoverage: "bounded_sufficient" },
    }), deps());
    expect(result.scored.verdict).toBe("safe");
  });

  it("allows a short authenticated official Apple notification when truncation is the only limitation", () => {
    const result = scanMessage(envelope({
      from: { displayName: "iCloud", address: "noreply@email.apple.com", domain: "email.apple.com" },
      subject: "Your iCloud storage is full",
      textPreview: "Your iCloud storage is full. Review your storage plan and remove files you no longer need.",
      listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
      parseStatus: "partial",
      parseNotes: [boundedNote],
      diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 50000, encoding: "multipart", contentCoverage: "insufficient" },
    }), deps());
    expect(result.scored.verdict).toBe("safe");
  });

  it("allows an authenticated official brand routed through Apple Private Relay", () => {
    const result = scanMessage(envelope({
      from: {
        displayName: "foodpanda",
        address: "contact_at_info_foodpanda_pk_29xqmt77nd_a6dc6b02@privaterelay.appleid.com",
        domain: "privaterelay.appleid.com",
      },
      subject: "Craving something delicious?",
      textPreview: "Open foodpanda to find restaurants and grocery deals near you. Manage your email preferences at any time.",
      listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
      parseStatus: "partial",
      parseNotes: [boundedNote],
      diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 50000, encoding: "multipart", contentCoverage: "insufficient" },
    }), deps());
    expect(result.scored.verdict).toBe("safe");
  });

  it("keeps an unrelated private-relay alias Unknown", () => {
    const result = scanMessage(envelope({
      from: {
        displayName: "foodpanda",
        address: "unrelated_alias_123@privaterelay.appleid.com",
        domain: "privaterelay.appleid.com",
      },
      subject: "Craving something delicious?",
      textPreview: "Open foodpanda to find restaurants and grocery deals near you. Manage your email preferences at any time.",
      listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
      parseStatus: "partial",
      parseNotes: [boundedNote],
      diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 50000, encoding: "multipart", contentCoverage: "insufficient" },
    }), deps());
    expect(result.scored.verdict).toBe("unknown");
  });

  it("keeps bounded unauthenticated official mail Unknown", () => {
    const result = scanMessage(envelope({
      from: { displayName: "Apple", address: "noreply@email.apple.com", domain: "email.apple.com" },
      authentication: { providerTrust: "trusted", spf: "unknown", dkim: "unknown", dmarc: "unknown", arc: "unknown" },
      textPreview: "Your Apple Account information has been updated. Review the security details in your account.",
      listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
      parseStatus: "partial",
      parseNotes: [boundedNote],
      diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 40000, encoding: "multipart", contentCoverage: "insufficient" },
    }), deps());
    expect(result.scored.verdict).toBe("unknown");
  });

  it("does not treat MIME download failure as bounded readable content", () => {
    const result = scanMessage(envelope({
      from: { displayName: "Apple", address: "noreply@email.apple.com", domain: "email.apple.com" },
      textPreview: "Your Apple Account information has been updated. Review the security details in your account.",
      listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
      parseStatus: "partial",
      parseNotes: ["Readable MIME part could not be downloaded: connection reset"],
      diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 40000, encoding: "multipart", contentCoverage: "insufficient" },
    }), deps());
    expect(result.scored.verdict).toBe("unknown");
  });
});

describe("real inbox lure regressions", () => {
  it("flags first-contact romance subjects from free-mail senders", () => {
    const result = messageIntentLayer(envelope({
      from: { displayName: "Julia", address: "julia@gmail.com", domain: "gmail.com" },
      subject: "Wanna see photos me",
      listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    }));
    expect(result.evidence.some((item) => item.code === "UNSOLICITED_ROMANCE_LURE")).toBe(true);
  });

  it("flags unusually high evaluator shopper offers", () => {
    const result = messageIntentLayer(envelope({ subject: "Earn $750 as Evaluator Shopper" }));
    expect(result.evidence.some((item) => item.code === "UNSOLICITED_HIGH_PAY_JOB")).toBe(true);
  });

  it("does not call a normal StreamYard registration email a callback scam", () => {
    const result = messageIntentLayer(envelope({
      subject: "Registration confirmation",
      textPreview: "Your subscription is active. Contact support at (212) 555-0100 if you need help.",
    }));
    expect(result.evidence.some((item) => item.code === "CALLBACK_SCAM_INTENT")).toBe(false);
  });

  it("does not flag an authenticated official Instagram lock notice as credential phishing", () => {
    const result = scanMessage(envelope({
      from: { displayName: "Instagram", address: "security@mail.instagram.com", domain: "mail.instagram.com" },
      subject: "Action required: Your Instagram account has been locked",
      textPreview: "Verify your account. Your account has been locked. Click below to confirm your identity.",
      listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    }), deps());
    expect(result.scored.evidence.some((item) => item.code === "CREDENTIAL_PHISH_INTENT")).toBe(false);
    expect(result.scored.verdict).toBe("safe");
  });

  it("still flags an Instagram lock lure from an unrelated sender domain", () => {
    const result = scanMessage(envelope({
      from: { displayName: "Instagram", address: "security@account-alerts.example", domain: "account-alerts.example" },
      subject: "Action required: Your Instagram account has been locked",
      textPreview: "Verify your account. Your account has been locked. Click below to confirm your identity.",
      listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    }), deps());
    expect(result.scored.evidence.some((item) => item.code === "CREDENTIAL_PHISH_INTENT")).toBe(true);
    expect(result.scored.evidence.some((item) => item.code === "BRAND_DOMAIN_MISMATCH")).toBe(true);
    expect(result.scored.verdict).toBe("high_risk");
  });
});
