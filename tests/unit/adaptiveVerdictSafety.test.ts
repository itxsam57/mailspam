import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { campaignFingerprint } from "../../server/src/community/fingerprint.js";
import { LEGITIMATE_RULE_PREFIX } from "../../server/src/community/feedback.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import type { SignedFeedEntry } from "../../server/src/engine/layers/globalIntelligence.js";

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  return {
    provider: "imap",
    accountProof: "proof",
    messageId: "adaptive-message",
    providerNativeId: "adaptive-native",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: {
      displayName: "Updates",
      address: "updates@example.test",
      domain: "example.test",
    },
    replyTo: null,
    subject: "Weekly account update",
    date: new Date(0).toISOString(),
    authentication: { providerTrust: "trusted", spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview: "Routine authenticated account information with no payment, credential, or urgent action request.",
    htmlSignals: null,
    links: [
      {
        visibleText: "Reference one",
        rawUrl: "not a url one",
        normalizedUrl: "not a url one",
        claimedBrand: null,
        brandDomainMismatch: null,
      },
      {
        visibleText: "Reference two",
        rawUrl: "not a url two",
        normalizedUrl: "not a url two",
        claimedBrand: null,
        brandDomainMismatch: null,
      },
    ],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: {
      fetchedAt: new Date(0).toISOString(),
      sizeBytes: 800,
      encoding: "plain",
      contentCoverage: "complete",
    },
    ...overrides,
  };
}

function scan(input: CanonicalEnvelope, policy: InMemoryPersonalPolicyStore, entries: SignedFeedEntry[] = []) {
  return scanMessage(input, {
    personalPolicy: policy,
    threatFeed: { getVerifiedEntries: () => entries },
  });
}

function legitimateEntry(input: CanonicalEnvelope): SignedFeedEntry {
  return {
    type: "campaign",
    value: campaignFingerprint(input),
    confirmedThreat: false,
    ruleId: `${LEGITIMATE_RULE_PREFIX}test-rule`,
    independentReports: 10,
  };
}

describe("adaptive legitimate learning safety", () => {
  it("keeps weak noisy context at Review before learning", () => {
    const result = scan(envelope(), new InMemoryPersonalPolicyStore());
    expect(result.scored.evidence.filter((item) => item.code === "MALFORMED_URL")).toHaveLength(2);
    expect(result.scored.score).toBe(2);
    expect(result.scored.verdict).toBe("review");
  });

  it("lets local sender trust suppress only the same weak contextual Review", () => {
    const input = envelope();
    const policy = new InMemoryPersonalPolicyStore();
    policy.trustSender(input.from.address!);
    const result = scan(input, policy);
    expect(result.scored.evidence).toContainEqual(expect.objectContaining({ code: "TRUSTED_SENDER", scoreContribution: 0 }));
    expect(result.scored.score).toBe(2);
    expect(result.scored.verdict).toBe("safe");
  });

  it("lets signed legitimate campaign consensus suppress only weak contextual Review", () => {
    const input = envelope();
    const result = scan(input, new InMemoryPersonalPolicyStore(), [legitimateEntry(input)]);
    expect(result.scored.evidence).toContainEqual(expect.objectContaining({ code: "GLOBAL_LEGITIMATE_CONSENSUS", scoreContribution: 0 }));
    expect(result.scored.verdict).toBe("safe");
  });

  it("never lets learned legitimacy suppress provider Spam/Junk placement", () => {
    const input = envelope({ folder: "spam", providerFolderName: "Junk" });
    const result = scan(input, new InMemoryPersonalPolicyStore(), [legitimateEntry(input)]);
    expect(result.scored.evidence).toContainEqual(expect.objectContaining({ code: "PROVIDER_SPAM_JUNK_PLACEMENT" }));
    expect(result.scored.verdict).toBe("review");
  });

  it("never lets learned legitimacy suppress authentication failure", () => {
    const input = envelope({
      authentication: { providerTrust: "trusted", spf: "fail", dkim: "fail", dmarc: "fail", arc: "none" },
    });
    const result = scan(input, new InMemoryPersonalPolicyStore(), [legitimateEntry(input)]);
    expect(result.scored.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "DMARC_FAIL" }),
      expect.objectContaining({ code: "SPF_DKIM_BOTH_FAIL" }),
    ]));
    expect(result.scored.verdict).toBe("high_risk");
  });

  it("never lets learned legitimacy suppress strong scam intent", () => {
    const input = envelope({
      subject: "Invoice renewed - call now",
      textPreview: "Your subscription renewed. If you did not authorize this charge call us now at 202-555-0198.",
    });
    const policy = new InMemoryPersonalPolicyStore();
    policy.trustSender(input.from.address!);
    const result = scan(input, policy);
    expect(result.scored.evidence).toContainEqual(expect.objectContaining({ code: "CALLBACK_SCAM_INTENT" }));
    expect(result.scored.verdict).not.toBe("safe");
  });

  it("never lets local trust or signed legitimate consensus suppress gift-card code exfiltration", () => {
    const input = envelope({
      subject: "Quick request",
      textPreview: "Buy $500 in Apple gift cards today. Send clear photos of the codes. Do not call; keep this between us.",
      links: [],
    });
    const policy = new InMemoryPersonalPolicyStore();
    policy.trustSender(input.from.address!);
    const result = scan(input, policy, [legitimateEntry(input)]);
    const codes = new Set(result.scored.evidence.map((item) => item.code));

    expect(codes.has("TRUSTED_SENDER")).toBe(true);
    expect(codes.has("GLOBAL_LEGITIMATE_CONSENSUS")).toBe(true);
    expect(codes.has("GIFT_CARD_CODE_EXFILTRATION")).toBe(true);
    expect(codes.has("SECRECY_PAYMENT_DIVERSION")).toBe(true);
    expect(result.scored.verdict).toBe("high_risk");
  });

  it("never lets positive consensus override a signed threat warning for the same campaign", () => {
    const input = envelope();
    const entries: SignedFeedEntry[] = [
      legitimateEntry(input),
      {
        type: "campaign",
        value: campaignFingerprint(input),
        confirmedThreat: false,
        ruleId: "community:warning-test",
        independentReports: 3,
      },
    ];
    const result = scan(input, new InMemoryPersonalPolicyStore(), entries);
    expect(result.scored.evidence).toContainEqual(expect.objectContaining({ code: "GLOBAL_WARNING_MATCH" }));
    expect(result.scored.verdict).toBe("review");
  });

  it("never lets positive consensus override a globally confirmed threat", () => {
    const input = envelope();
    const entries: SignedFeedEntry[] = [
      legitimateEntry(input),
      {
        type: "campaign",
        value: campaignFingerprint(input),
        confirmedThreat: true,
        ruleId: "community:confirmed-test",
        independentReports: 5,
      },
    ];
    const result = scan(input, new InMemoryPersonalPolicyStore(), entries);
    expect(result.scored.verdict).toBe("confirmed_threat");
    expect(result.action).toBe("auto_trash_allowed");
  });
});
