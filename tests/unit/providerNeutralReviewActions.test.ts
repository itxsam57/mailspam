import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope, Provider } from "../../server/src/canonical/envelope.js";
import { createAdapter } from "../../server/src/api/adapterConfig.js";
import { identityImpersonationLayer } from "../../server/src/engine/layers/identityImpersonation.js";
import { messageIntentLayer } from "../../server/src/engine/layers/messageIntent.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";
import { messageExceptionKey } from "../../server/src/workflows/messageReview.js";
import { quickScan } from "../../server/src/workflows/scanWorkflows.js";

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  return {
    provider: "gmail",
    accountProof: "account-proof-a",
    messageId: "message-id-a",
    providerNativeId: "native-a",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Example", address: "sender@regional-mail.example", domain: "regional-mail.example" },
    replyTo: null,
    subject: "Example message",
    date: new Date(0).toISOString(),
    authentication: { spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview: "Readable message content for deterministic local review.",
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 1000, encoding: "plain", contentCoverage: "complete" },
    ...overrides,
  };
}

const threatFeed = { getVerifiedEntries: () => [] };

describe("exact-message review decisions", () => {
  it("creates an opaque key without preserving private mailbox values", () => {
    const message = envelope();
    const key = messageExceptionKey(message);
    expect(key).toMatch(/^message:[a-f0-9]{64}$/);
    expect(key).not.toContain(message.accountProof);
    expect(key).not.toContain(message.messageId);
    expect(key).not.toContain(message.from.address!);
  });

  it("marks only the selected message Safe without trusting another message from the sender", () => {
    const policy = new InMemoryPersonalPolicyStore();
    const first = envelope({
      messageId: "first",
      providerNativeId: "native-first",
      subject: "Actual person.",
      from: { displayName: "Unknown", address: "person@regional-mail.example", domain: "regional-mail.example" },
    });
    const second = envelope({
      messageId: "second",
      providerNativeId: "native-second",
      subject: "Actual person.",
      from: first.from,
    });

    expect(scanMessage(first, { personalPolicy: policy, threatFeed }).scored.verdict).toBe("review");
    policy.approveException(messageExceptionKey(first));
    expect(scanMessage(first, { personalPolicy: policy, threatFeed }).scored.verdict).toBe("safe");
    expect(scanMessage(second, { personalPolicy: policy, threatFeed }).scored.verdict).toBe("review");
    expect(policy.isTrustedSender(first.from.address!)).toBe(false);
  });

  it("keeps an explicit personal block authoritative over trust and message approval", () => {
    const policy = new InMemoryPersonalPolicyStore();
    const message = envelope();
    policy.approveException(messageExceptionKey(message));
    policy.trustSender(message.from.address!);
    policy.blockSender(message.from.address!);
    const result = scanMessage(message, { personalPolicy: policy, threatFeed });
    expect(result.scored.verdict).toBe("confirmed_threat");
    expect(result.scored.evidence.some((item) => item.code === "BLOCKED_SENDER")).toBe(true);
  });
});

describe("provider-independent classification regressions", () => {
  it("does not treat a short ordinary verb as an organization identity", () => {
    const result = identityImpersonationLayer(envelope({
      from: { displayName: "Find My", address: "noreply@identity.example", domain: "identity.example" },
      subject: "Find My has been disabled on this device",
    }));
    expect(result.evidence.some((item) => item.code === "BRAND_DOMAIN_MISMATCH")).toBe(false);
  });

  it("detects a first-contact romance lure from any provider domain", () => {
    const result = messageIntentLayer(envelope({
      from: { displayName: "Person", address: "person@mobile-mail.example", domain: "mobile-mail.example" },
      subject: "What if I said I want you… would you believe me?",
    }));
    expect(result.evidence).toContainEqual(expect.objectContaining({ code: "UNSOLICITED_ROMANCE_LURE" }));
  });

  it("detects a generic free tool/reward claim without a known brand", () => {
    const result = messageIntentLayer(envelope({
      from: { displayName: "Offers", address: "offers@unknown.example", domain: "unknown.example" },
      subject: "Free Stanley Tool Set",
    }));
    expect(result.evidence).toContainEqual(expect.objectContaining({ code: "FREE_REWARD_LURE" }));
  });
});

describe("all adapter options share the same scan action contract", () => {
  for (const provider of ["gmail", "icloud", "outlook", "yahoo", "imap"] as Provider[]) {
    it(`${provider} fixture emits review and unsubscribe context through the canonical workflow`, async () => {
      const adapter = createAdapter({ provider, mode: "fixture" });
      const policy = new InMemoryPersonalPolicyStore();
      const pages = [];
      for await (const page of quickScan(adapter, { personalPolicy: policy, threatFeed }, new AbortController().signal, 10)) {
        pages.push(page);
      }
      expect(pages).toHaveLength(1);
      expect(pages[0]!.diagnosticSummaries.length).toBeGreaterThan(0);
      for (const summary of pages[0]!.diagnosticSummaries) {
        expect(summary.actionContext.exceptionKey).toMatch(/^message:[a-f0-9]{64}$/);
        expect(summary.actionContext.providerNativeId).toBeTruthy();
        expect(summary.actionContext.unsubscribe).toHaveProperty("available");
      }
    });
  }
});
