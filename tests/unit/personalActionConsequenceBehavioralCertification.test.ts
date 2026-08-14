import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { campaignFingerprint } from "../../server/src/community/fingerprint.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import type { ThreatFeedCache } from "../../server/src/engine/layers/globalIntelligence.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";
import { messageExceptionKey } from "../../server/src/workflows/messageReview.js";

const emptyFeed: ThreatFeedCache = { getVerifiedEntries: () => [] };

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  const base: CanonicalEnvelope = {
    provider: "gmail",
    accountProof: "personal-action-cert",
    messageId: "<personal-action-cert@example.test>",
    providerNativeId: "personal-action-native",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Routine Sender", address: "sender@example.test", domain: "example.test" },
    replyTo: null,
    subject: "Routine correspondence",
    date: "2026-08-14T10:00:00.000Z",
    authentication: {
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      arc: "none",
      providerTrust: "trusted",
      rawHeader: "mx.receiver.example; spf=pass smtp.mailfrom=example.test; dkim=pass header.d=example.test; dmarc=pass header.from=example.test",
    },
    textPreview: "Routine authenticated correspondence with no credential request, payment pressure, urgent transfer, installation demand, or security-sensitive instruction.",
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: {
      isFirstContact: false,
      threadContinuityBroken: false,
      replyToChangedMidThread: false,
      relationshipPriorMessages: 12,
      relationshipPriorAuthenticatedMessages: 12,
      relationshipPriorSafeMessages: 12,
      relationshipPriorSuspiciousMessages: 0,
      hasEstablishedSenderHistory: true,
      relationshipAuthenticationDowngrade: false,
      replyToChangedFromRelationshipHistory: false,
    },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: { fetchedAt: "2026-08-14T10:00:00.000Z", sizeBytes: 512, encoding: "plain", contentCoverage: "complete" },
  };
  return {
    ...base,
    ...overrides,
    from: overrides.from ?? base.from,
    authentication: overrides.authentication ?? base.authentication,
    listHeaders: overrides.listHeaders ?? base.listHeaders,
    threadContext: overrides.threadContext ?? base.threadContext,
    diagnostics: overrides.diagnostics ?? base.diagnostics,
  };
}

function scan(candidate: CanonicalEnvelope, policy: InMemoryPersonalPolicyStore) {
  return scanMessage(candidate, { personalPolicy: policy, threatFeed: emptyFeed });
}

describe("durable personal action consequences", () => {
  it("Block sender changes the next matching message to Confirmed Threat, and unblock reverses only that personal rule", () => {
    const policy = new InMemoryPersonalPolicyStore();
    const candidate = envelope();
    expect(scan(candidate, policy).scored.verdict).toBe("safe");

    policy.blockSender(candidate.from.address!);
    const blocked = scan({ ...candidate, messageId: "<future-sender-block@example.test>", providerNativeId: "future-sender-block" }, policy);
    expect(blocked.scored.verdict).toBe("confirmed_threat");
    expect(blocked.scored.confirmedByRule).toBe(true);
    expect(blocked.action).toBe("auto_trash_allowed");
    expect(blocked.scored.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ layer: "personal_rules", code: "PERSONAL_BLOCKED_SENDER", scoreContribution: 100 }),
    ]));

    expect(policy.unblockSender(candidate.from.address!)).toBe(true);
    const unblocked = scan({ ...candidate, messageId: "<after-sender-unblock@example.test>", providerNativeId: "after-sender-unblock" }, policy);
    expect(unblocked.scored.verdict).toBe("safe");
    expect(unblocked.scored.confirmedByRule).toBe(false);
  });

  it("Block domain protects future mail from another address on that domain, then domain revoke removes the confirmation", () => {
    const policy = new InMemoryPersonalPolicyStore();
    const candidate = envelope();
    policy.blockDomain(candidate.from.domain!);

    const anotherSender = envelope({
      messageId: "<future-domain-block@example.test>",
      providerNativeId: "future-domain-block",
      from: { displayName: "Different Sender", address: "another@example.test", domain: "example.test" },
    });
    const blocked = scan(anotherSender, policy);
    expect(blocked.scored.verdict).toBe("confirmed_threat");
    expect(blocked.scored.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "PERSONAL_BLOCKED_DOMAIN", scoreContribution: 100 }),
    ]));

    expect(policy.unblockDomain("example.test")).toBe(true);
    expect(scan(anotherSender, policy).scored.verdict).toBe("safe");
  });

  it("Report Scam campaign protection survives sender/address changes when the stable campaign fingerprint still matches", () => {
    const policy = new InMemoryPersonalPolicyStore();
    const original = envelope({
      subject: "Security verification notice",
      from: { displayName: "Delivery A", address: "first@delivery-one.example", domain: "delivery-one.example" },
      links: [{
        visibleText: "Verify",
        rawUrl: "https://campaign-infra.example/verify?id=1",
        normalizedUrl: "https://campaign-infra.example/verify?id=1",
        claimedBrand: null,
        brandDomainMismatch: null,
        source: "body",
      }],
    });
    const fingerprint = campaignFingerprint(original);
    policy.reportCampaign(fingerprint);

    const rotatedDelivery = envelope({
      messageId: "<future-campaign@example.test>",
      providerNativeId: "future-campaign",
      subject: original.subject,
      from: { displayName: "Delivery B", address: "second@delivery-two.example", domain: "delivery-two.example" },
      links: [{
        visibleText: "Verify",
        rawUrl: "https://campaign-infra.example/verify?id=999",
        normalizedUrl: "https://campaign-infra.example/verify?id=999",
        claimedBrand: null,
        brandDomainMismatch: null,
        source: "body",
      }],
    });
    expect(campaignFingerprint(rotatedDelivery)).toBe(fingerprint);
    const protectedResult = scan(rotatedDelivery, policy);
    expect(protectedResult.scored.verdict).toBe("confirmed_threat");
    expect(protectedResult.action).toBe("auto_trash_allowed");
    expect(protectedResult.scored.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "PERSONAL_REPORTED_SCAM_CAMPAIGN", scoreContribution: 100 }),
    ]));
  });

  it("Mark Safe applies only to the exact message and clears ordinary Review, not later messages from the same sender", () => {
    const policy = new InMemoryPersonalPolicyStore();
    const reviewed = envelope({
      replyTo: { displayName: null, address: "reply@other.example", domain: "other.example" },
    });
    expect(scan(reviewed, policy).scored.verdict).toBe("review");

    policy.approveException(messageExceptionKey(reviewed));
    expect(scan(reviewed, policy).scored.verdict).toBe("safe");

    const later = { ...reviewed, messageId: "<different-message@example.test>", providerNativeId: "different-message" };
    expect(messageExceptionKey(later)).not.toBe(messageExceptionKey(reviewed));
    expect(scan(later, policy).scored.verdict).toBe("review");
  });

  it("Trust Sender suppresses only weak authenticated nuisance context and does not suppress a +2 security signal", () => {
    const policy = new InMemoryPersonalPolicyStore();
    const weakArchiveContext = envelope({
      attachments: [
        { name: "documents-one.zip", mimeType: "application/zip", sizeBytes: 120, extension: "zip", sha256: "1".repeat(64), suspiciousNamePattern: false },
        { name: "documents-two.zip", mimeType: "application/zip", sizeBytes: 120, extension: "zip", sha256: "2".repeat(64), suspiciousNamePattern: false },
      ],
    });
    expect(scan(weakArchiveContext, policy).scored.verdict).toBe("review");

    policy.trustSender(weakArchiveContext.from.address!);
    const trustedWeak = scan(weakArchiveContext, policy);
    expect(trustedWeak.scored.verdict).toBe("safe");
    expect(trustedWeak.scored.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "PERSONAL_TRUSTED_SENDER", scoreContribution: 0 }),
    ]));

    const replyToMismatch = envelope({
      messageId: "<trusted-but-mismatch@example.test>",
      providerNativeId: "trusted-but-mismatch",
      replyTo: { displayName: null, address: "reply@other.example", domain: "other.example" },
    });
    const stillReview = scan(replyToMismatch, policy);
    expect(stillReview.scored.verdict).toBe("review");
    expect(stillReview.scored.evidence.some((item) => item.code === "REPLY_TO_MISMATCH" && item.scoreContribution === 2)).toBe(true);
  });

  it("Trust and Mark Safe never suppress a verified intelligence match", () => {
    const candidate = envelope();
    const policy = new InMemoryPersonalPolicyStore();
    policy.trustSender(candidate.from.address!);
    policy.approveException(messageExceptionKey(candidate));
    const feed: ThreatFeedCache = {
      getVerifiedEntries: () => [{
        type: "sender",
        value: candidate.from.address!,
        confirmedThreat: true,
        ruleId: "certified-hard-threat",
        independentReports: 8,
      }],
    };
    const result = scanMessage(candidate, { personalPolicy: policy, threatFeed: feed });
    expect(result.scored.verdict).toBe("confirmed_threat");
    expect(result.action).toBe("auto_trash_allowed");
  });
});
