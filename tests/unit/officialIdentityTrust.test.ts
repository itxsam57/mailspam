import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import {
  hasDeterministicOfficialIdentity,
  isDirectOfficialSenderDomain,
  isOfficialPrivateRelaySender,
} from "../../server/src/engine/layers/identityImpersonation.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";

function message(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  return {
    provider: "icloud",
    accountProof: "proof",
    messageId: "message-id",
    providerNativeId: "native-id",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Example", address: "sender@example.com", domain: "example.com" },
    replyTo: null,
    subject: "Example",
    date: new Date(0).toISOString(),
    authentication: { spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview: "A readable security or marketing notification with enough visible content for bounded analysis.",
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "partial",
    parseNotes: ["Readable text was bounded to 24576 bytes."],
    diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 50000, encoding: "multipart", contentCoverage: "insufficient" },
    ...overrides,
  };
}

const dependencies = {
  personalPolicy: new InMemoryPersonalPolicyStore(),
  threatFeed: { getVerifiedEntries: () => [] },
};

describe("official identity trust boundary", () => {
  it("never treats a personal Gmail address as an official sender identity", () => {
    const gmail = message({
      from: { displayName: "Julia", address: "julia@gmail.com", domain: "gmail.com" },
      subject: "Hello",
    });
    expect(isDirectOfficialSenderDomain(gmail)).toBe(false);
    expect(hasDeterministicOfficialIdentity(gmail)).toBe(false);
    expect(scanMessage(gmail, dependencies).scored.verdict).toBe("unknown");
  });

  it("recognizes a short authenticated X security notice", () => {
    const xNotice = message({
      from: { displayName: "X", address: "verify@x.com", domain: "x.com" },
      subject: "New login to X from an iPhone",
    });
    expect(isDirectOfficialSenderDomain(xNotice)).toBe(true);
    expect(scanMessage(xNotice, dependencies).scored.verdict).toBe("safe");
  });

  it("recognizes the claimed brand encoded in an Apple Private Relay alias", () => {
    const relay = message({
      from: {
        displayName: "Alibaba",
        address: "noreply_at_order_alibaba_com_mcgrz8c4g9_caed9795@privaterelay.appleid.com",
        domain: "privaterelay.appleid.com",
      },
      subject: "Trending Best-Selling Products List",
    });
    expect(isOfficialPrivateRelaySender(relay)).toBe(true);
    expect(scanMessage(relay, dependencies).scored.verdict).toBe("safe");
  });

  it("does not trust a private-relay alias that omits the claimed brand domain", () => {
    const relay = message({
      from: {
        displayName: "Alibaba",
        address: "random_alias_123@privaterelay.appleid.com",
        domain: "privaterelay.appleid.com",
      },
      subject: "Trending Best-Selling Products List",
    });
    expect(isOfficialPrivateRelaySender(relay)).toBe(false);
    expect(scanMessage(relay, dependencies).scored.verdict).toBe("unknown");
  });

  it("suppresses generic credential intent only for an authenticated official Instagram domain", () => {
    const official = message({
      parseStatus: "complete",
      parseNotes: [],
      diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 2000, encoding: "plain", contentCoverage: "complete" },
      from: { displayName: "Instagram", address: "security@mail.instagram.com", domain: "mail.instagram.com" },
      subject: "Action required: Your Instagram account has been locked",
      textPreview: "Verify your account. Your account has been locked. Click below to confirm your identity.",
    });
    const officialResult = scanMessage(official, dependencies);
    expect(officialResult.scored.evidence.some((item) => item.code === "CREDENTIAL_PHISH_INTENT")).toBe(false);
    expect(officialResult.scored.verdict).toBe("safe");

    const spoof = message({
      parseStatus: "complete",
      parseNotes: [],
      diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 2000, encoding: "plain", contentCoverage: "complete" },
      from: { displayName: "Instagram", address: "security@account-alerts.example", domain: "account-alerts.example" },
      subject: "Action required: Your Instagram account has been locked",
      textPreview: "Verify your account. Your account has been locked. Click below to confirm your identity.",
    });
    const spoofResult = scanMessage(spoof, dependencies);
    expect(spoofResult.scored.evidence.some((item) => item.code === "CREDENTIAL_PHISH_INTENT")).toBe(true);
    expect(spoofResult.scored.evidence.some((item) => item.code === "BRAND_DOMAIN_MISMATCH")).toBe(true);
    expect(spoofResult.scored.verdict).toBe("high_risk");
  });
});
