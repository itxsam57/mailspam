import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import type { SignedFeedEntry } from "../../server/src/engine/layers/globalIntelligence.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";

function envelope(textPreview: string): CanonicalEnvelope {
  return {
    provider: "imap",
    accountProof: "structural-ownership-proof",
    messageId: "structural-ownership-message",
    providerNativeId: "structural-ownership-native",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: null, address: "notice@sender.example", domain: "sender.example" },
    replyTo: null,
    subject: "",
    date: new Date(0).toISOString(),
    authentication: { providerTrust: "unknown", spf: "unknown", dkim: "unknown", dmarc: "unknown", arc: "unknown" },
    textPreview,
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 512, encoding: "plain", contentCoverage: "complete" },
  };
}

function scan(text: string) {
  return scanMessage(envelope(text), {
    personalPolicy: new InMemoryPersonalPolicyStore(),
    threatFeed: { getVerifiedEntries: () => [] as SignedFeedEntry[] },
  });
}

describe("structural evidence ownership", () => {
  it("keeps explicit irreversible crypto payment pressure high risk without legacy duplicate scoring", () => {
    const result = scan("Send 800 USDT to the wallet within 30 minutes to release the payment review. This transfer cannot be reversed.");
    const evidence = result.scored.evidence;

    expect(evidence).toContainEqual(expect.objectContaining({ code: "IRREVERSIBLE_PAYMENT_PRESSURE" }));
    expect(evidence.some((item) => item.code === "CRYPTO_SCAM_INTENT")).toBe(false);
    expect(result.scored.verdict).toBe("high_risk");
  });

  it("does not turn a passive crypto timing statement into scam intent", () => {
    const result = scan("Bitcoin market prices will be refreshed within 30 minutes. No payment, transfer, wallet action, or response is requested.");

    expect(result.scored.evidence.some((item) => item.code === "CRYPTO_SCAM_INTENT")).toBe(false);
    expect(result.scored.evidence.some((item) => item.code === "IRREVERSIBLE_PAYMENT_PRESSURE")).toBe(false);
    expect(result.scored.verdict).not.toBe("high_risk");
  });
});
