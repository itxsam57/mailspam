import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { normalizeImapFolder, providerFolderPath } from "../../server/src/adapters/imap/folderNames.js";
import { sameOrganizationalDomain } from "../../server/src/util/domainRelation.js";
import { identityImpersonationLayer } from "../../server/src/engine/layers/identityImpersonation.js";
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
    authentication: { spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
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
});

describe("provider-neutral unsubscribe availability", () => {
  it("prefers RFC 8058 one-click when declared", () => {
    const capability = unsubscribeCapability(envelope({
      listHeaders: {
        listId: "list.example",
        listUnsubscribe: "<mailto:leave@example.com>, <https://example.com/unsubscribe?id=1>",
        listUnsubscribePost: "List-Unsubscribe=One-Click",
      },
    }));
    expect(capability).toMatchObject({ available: true, method: "one_click_post", source: "list_header" });
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
      parseNotes: ["Readable text was bounded to 24576 bytes."],
      diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 40000, encoding: "multipart", contentCoverage: "bounded_sufficient" },
    }), { personalPolicy: new InMemoryPersonalPolicyStore(), threatFeed });
    expect(result.scored.verdict).toBe("safe");
  });

  it("keeps bounded unauthenticated mail Unknown", () => {
    const result = scanMessage(envelope({
      authentication: { spf: "unknown", dkim: "unknown", dmarc: "unknown", arc: "unknown" },
      parseStatus: "partial",
      parseNotes: ["Readable text was bounded to 24576 bytes."],
      diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 40000, encoding: "multipart", contentCoverage: "bounded_sufficient" },
    }), { personalPolicy: new InMemoryPersonalPolicyStore(), threatFeed });
    expect(result.scored.verdict).toBe("unknown");
  });
});

describe("real inbox lure regressions", () => {
  it("flags first-contact romance subjects from free-mail senders", () => {
    const result = messageIntentLayer(envelope({
      from: { displayName: "Julia", address: "julia@example@gmail.com", domain: "gmail.com" },
      subject: "Wanna see photos me",
      listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    }));
    expect(result.evidence.some((item) => item.code === "UNSOLICITED_ROMANCE_LURE")).toBe(true);
  });

  it("flags unusually high evaluator shopper offers", () => {
    const result = messageIntentLayer(envelope({
      subject: "Earn $750 as Evaluator Shopper",
    }));
    expect(result.evidence.some((item) => item.code === "UNSOLICITED_HIGH_PAY_JOB")).toBe(true);
  });

  it("does not call a normal StreamYard registration email a callback scam", () => {
    const result = messageIntentLayer(envelope({
      subject: "Registration confirmation",
      textPreview: "Your subscription is active. Contact support at (212) 555-0100 if you need help.",
    }));
    expect(result.evidence.some((item) => item.code === "CALLBACK_SCAM_INTENT")).toBe(false);
  });
});
