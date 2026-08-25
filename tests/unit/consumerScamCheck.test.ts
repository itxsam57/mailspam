import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import {
  ConsumerScamCheckError,
  evaluateConsumerScamCheck,
} from "../../server/src/consumer/scamCheck.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import type { SignedFeedEntry } from "../../server/src/engine/layers/globalIntelligence.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";

const giftCardScam = "Your manager needs $500 in Apple gift cards today. Send clear photos of the codes. Do not call; keep this between us.";

function connectedEnvelope(textPreview: string): CanonicalEnvelope {
  return {
    provider: "gmail",
    accountProof: "shared-core-parity-proof",
    messageId: "shared-core-parity-message",
    providerNativeId: "shared-core-parity-native",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Project Manager", address: "manager@work.example", domain: "work.example" },
    replyTo: null,
    subject: "Private purchase request",
    date: new Date(0).toISOString(),
    authentication: { providerTrust: "trusted", spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview,
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 1024, encoding: "plain", contentCoverage: "complete" },
  };
}

describe("consumer Scam Check", () => {
  it("uses the existing deterministic engine for full-context callback and link risk", () => {
    const result = evaluateConsumerScamCheck({
      schemaVersion: 1,
      kind: "message",
      subject: "Subscription renewed",
      text: "Your subscription renewed. If you did not authorize this, call us now at (555) 123-4567. Review details at http://192.0.2.44/login",
    });

    expect(result.evidence.some((item) => item.code === "CALLBACK_SCAM_INTENT")).toBe(true);
    expect(result.evidence.some((item) => item.code === "RAW_IP_HOST")).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(6);
    expect(result.verdict).toBe("high_risk");
    expect(result.action).toBe("allow_one_click_block");
    expect(result.explanation.scamCategory).toBe("callback_refund");
    expect(result.explanation.evidenceStrength).toBe("strong");
    expect(result.explanation.safeNextActions.join(" ")).toMatch(/independently/i);
  });

  it("uses the same structural gift-card evidence for pasted and connected-mailbox content", () => {
    const pasted = evaluateConsumerScamCheck({
      schemaVersion: 1,
      kind: "message",
      subject: "Private purchase request",
      text: giftCardScam,
      sender: { displayName: "Project Manager", address: "manager@work.example" },
    });
    const connected = scanMessage(connectedEnvelope(giftCardScam), {
      personalPolicy: new InMemoryPersonalPolicyStore(),
      threatFeed: { getVerifiedEntries: () => [] as SignedFeedEntry[] },
    });

    expect(pasted.evidence.some((item) => item.code === "GIFT_CARD_CODE_EXFILTRATION")).toBe(true);
    expect(connected.scored.evidence.some((item) => item.code === "GIFT_CARD_CODE_EXFILTRATION")).toBe(true);
    expect(pasted.verdict).toBe("high_risk");
    expect(connected.scored.verdict).toBe("high_risk");
  });

  it("maps shared remote-access structural evidence into an existing consumer scam category", () => {
    const result = evaluateConsumerScamCheck({
      schemaVersion: 1,
      kind: "message",
      text: "Bank fraud team: install AnyDesk so we can secure the account and process the refund.",
    });

    expect(result.evidence.some((item) => item.code === "REMOTE_ACCESS_FINANCIAL_PRESSURE")).toBe(true);
    expect(result.explanation.scamCategory).toBe("callback_refund");
  });

  it("detects unsafe URL schemes without navigating to them", () => {
    const result = evaluateConsumerScamCheck({
      schemaVersion: 1,
      kind: "url",
      url: "javascript:alert(document.domain)",
    });

    expect(result.evidence.some((item) => item.code === "UNSAFE_LINK_SCHEME")).toBe(true);
    expect(["review", "high_risk"]).toContain(result.verdict);
  });

  it("canonicalizes whole percent-encoded web destinations before local link evidence", () => {
    const direct = evaluateConsumerScamCheck({
      schemaVersion: 1,
      kind: "url",
      url: "https%3A%2F%2Fshop.example%2Faccount%3Fmode%3Dreview",
    });
    const html = evaluateConsumerScamCheck({
      schemaVersion: 1,
      kind: "message",
      html: '<a href="https%3A%2F%2Fshop.example%2Faccount%3Fmode%3Dreview">Manage preferences</a>',
    });

    expect(direct.evidence.some((item) => item.code === "MALFORMED_URL")).toBe(false);
    expect(html.evidence.some((item) => item.code === "MALFORMED_URL")).toBe(false);
  });

  it("does not invent trusted mailbox authentication for submitted content", () => {
    const result = evaluateConsumerScamCheck({
      schemaVersion: 1,
      kind: "message",
      text: "Dinner is at seven. See you there.",
      sender: { displayName: "Alex", address: "alex@example.com" },
    });

    const transport = result.layerResults.find((layer) => layer.layer === "transport_auth");
    expect(transport?.incomplete).toBe(true);
    expect(result.explanation.limitations.join(" ")).toMatch(/does not have trusted mailbox transport\/authentication provenance/i);
    expect(result.confirmedByRule).toBe(false);
  });

  it("keeps personal policy and signed intelligence outside the untrusted request contract", () => {
    expect(() => evaluateConsumerScamCheck({
      schemaVersion: 1,
      kind: "message",
      text: "hello",
      personalPolicy: {
        blockedSenders: [],
        blockedDomains: [],
        trustedSenders: [],
        approvedExceptions: [],
        unsubscribedActions: [],
        reportedCampaigns: [],
      },
    })).toThrowError(ConsumerScamCheckError);
  });

  it("rejects empty message checks rather than returning a misleading safe result", () => {
    expect(() => evaluateConsumerScamCheck({
      schemaVersion: 1,
      kind: "message",
      text: "   ",
    })).toThrowError(ConsumerScamCheckError);
  });

  it("bounds submitted text before engine execution", () => {
    expect(() => evaluateConsumerScamCheck({
      schemaVersion: 1,
      kind: "message",
      text: "a".repeat(512 * 1024 + 1),
    })).toThrowError(ConsumerScamCheckError);
  });
});
