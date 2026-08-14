import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope, LinkInfo } from "../../server/src/canonical/envelope.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import type { ThreatFeedCache } from "../../server/src/engine/layers/globalIntelligence.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";
import { messageExceptionKey } from "../../server/src/workflows/messageReview.js";
import { applyProtectionSensitivity } from "../../server/src/consumer/protectionSensitivity.js";

const emptyFeed: ThreatFeedCache = { getVerifiedEntries: () => [] };

function link(url: string): LinkInfo {
  return {
    visibleText: url,
    rawUrl: url,
    normalizedUrl: url,
    claimedBrand: null,
    brandDomainMismatch: null,
    source: "body",
  };
}

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  const base: CanonicalEnvelope = {
    provider: "gmail",
    accountProof: "identity-cert-account",
    messageId: "<identity-cert@example.test>",
    providerNativeId: "identity-cert-native",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Acme Operations", address: "ops@acme.com", domain: "acme.com" },
    replyTo: null,
    subject: "Routine Acme operations notice",
    date: "2026-08-14T10:00:00.000Z",
    authentication: {
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      arc: "none",
      providerTrust: "trusted",
      rawHeader: "spf=pass smtp.mailfrom=acme.com; dkim=pass header.d=acme.com header.s=s1; dmarc=pass",
    },
    textPreview: "Routine authenticated operational correspondence. No password, payment, one-time code, recovery phrase, urgent transfer, or forced verification is requested.",
    htmlSignals: null,
    links: [link("https://portal.acme.com/notice")],
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
    diagnostics: {
      fetchedAt: "2026-08-14T10:00:00.000Z",
      sizeBytes: 900,
      encoding: "plain",
      contentCoverage: "complete",
    },
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

function scan(candidate: CanonicalEnvelope, policy = new InMemoryPersonalPolicyStore(), feed = emptyFeed) {
  return scanMessage(candidate, { personalPolicy: policy, threatFeed: feed });
}

describe("authentication + impersonation + intent behavioral certification", () => {
  it("keeps a fully authenticated aligned ordinary organizational message Safe", () => {
    const result = scan(envelope());
    expect(result.scored.verdict).toBe("safe");
    expect(result.action).toBe("none");
    expect(result.scored.confirmedByRule).toBe(false);
    expect(result.scored.evidence.filter((item) => item.scoreContribution > 0)).toEqual([]);
  });

  it("combines auth failure, explicit identity mismatch, credential pressure and insecure link into High Risk", () => {
    const candidate = envelope({
      from: { displayName: "Acme Security", address: "security@evil.example", domain: "evil.example" },
      subject: "Acme Security alert — portal: acme.com",
      authentication: {
        spf: "fail",
        dkim: "fail",
        dmarc: "fail",
        arc: "none",
        providerTrust: "trusted",
        rawHeader: "spf=fail smtp.mailfrom=evil.example; dkim=fail header.d=evil.example; dmarc=fail",
      },
      textPreview: "Verify your account within 24 hours. Click below to confirm your identity and enter your password or the account will be suspended.",
      links: [link("http://login.acme-security.evil.example/verify")],
      threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    });

    const result = scan(candidate);
    const codes = new Set(result.scored.evidence.map((item) => item.code));

    expect(result.scored.verdict).toBe("high_risk");
    expect(result.action).toBe("allow_one_click_block");
    expect(codes).toEqual(expect.objectContaining ? codes : codes);
    expect(codes.has("DMARC_FAIL")).toBe(true);
    expect(codes.has("SPF_DKIM_BOTH_FAIL")).toBe(true);
    expect(codes.has("EXPLICIT_DOMAIN_CLAIM_MISMATCH")).toBe(true);
    expect(codes.has("CREDENTIAL_PHISH_INTENT")).toBe(true);
    expect(codes.has("LINK_HTTP_SCHEME")).toBe(true);
  });

  it("does not let account-local Trust + exact-message Safe turn a multi-signal phishing message into Safe", () => {
    const candidate = envelope({
      from: { displayName: "Acme Security", address: "security@evil.example", domain: "evil.example" },
      subject: "Acme Security alert — portal: acme.com",
      authentication: {
        spf: "fail",
        dkim: "fail",
        dmarc: "fail",
        arc: "none",
        providerTrust: "trusted",
      },
      textPreview: "Verify your account within 24 hours. Click below to confirm your identity and enter your password or the account will be suspended.",
      links: [link("http://login.evil.example/verify")],
      threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    });
    const policy = new InMemoryPersonalPolicyStore();
    policy.trustSender(candidate.from.address!);
    policy.approveException(messageExceptionKey(candidate));

    const result = scan(candidate, policy);

    expect(result.scored.verdict).not.toBe("safe");
    expect(result.scored.evidence.some((item) => item.code === "DMARC_FAIL")).toBe(true);
    expect(result.scored.evidence.some((item) => item.code === "CREDENTIAL_PHISH_INTENT")).toBe(true);
  });

  it("lets a verified signed intelligence match override local Trust and exact-message Safe as a hard Confirmed Threat", () => {
    const candidate = envelope();
    const policy = new InMemoryPersonalPolicyStore();
    policy.trustSender(candidate.from.address!);
    policy.approveException(messageExceptionKey(candidate));
    const feed: ThreatFeedCache = {
      getVerifiedEntries: () => [{
        type: "sender",
        value: candidate.from.address!,
        confirmedThreat: true,
        ruleId: "certified-sender-threat",
        independentReports: 5,
      }],
    };

    const result = scan(candidate, policy, feed);

    expect(result.scored.verdict).toBe("confirmed_threat");
    expect(result.scored.confirmedByRule).toBe(true);
    expect(result.action).toBe("auto_trash_allowed");
  });

  it("treats a lone unrelated Reply-To as context rather than automatically calling an otherwise clean message malicious", () => {
    const candidate = envelope({
      replyTo: { displayName: null, address: "reply@support-other.example", domain: "support-other.example" },
    });
    const result = scan(candidate);

    expect(result.scored.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "REPLY_TO_MISMATCH", scoreContribution: 2 }),
    ]));
    expect(result.scored.verdict).toBe("safe");
    expect(result.action).toBe("none");
  });

  it("withholds Safe when bounded content cannot rely on trusted authentication provenance", () => {
    const candidate = envelope({
      authentication: { spf: "pass", dkim: "pass", dmarc: "pass", arc: "none", providerTrust: "unknown" },
      diagnostics: {
        fetchedAt: "2026-08-14T10:00:00.000Z",
        sizeBytes: 900,
        encoding: "plain",
        contentCoverage: "bounded_sufficient",
      },
    });
    const result = scan(candidate);

    expect(result.scored.verdict).toBe("unknown");
    expect(result.action).toBe("warn");
    const transport = result.scored.layerResults.find((item) => item.layer === "transport_auth");
    expect(transport?.incomplete).toBe(true);
  });

  it("never lets Low Noise hide a hard DMARC contradiction or rewrite the authoritative verdict/action", () => {
    const candidate = envelope({
      authentication: {
        spf: "pass",
        dkim: "pass",
        dmarc: "fail",
        arc: "none",
        providerTrust: "trusted",
      },
    });
    const result = scan(candidate);
    expect(result.scored.verdict).toBe("review");

    const lowNoise = applyProtectionSensitivity(result, "low_noise");
    expect(lowNoise.verdict).toBe(result.scored.verdict);
    expect(lowNoise.action).toBe(result.action);
    expect(lowNoise.hardSecuritySignal).toBe(true);
    expect(lowNoise.attention).toBe("alert");
    expect(lowNoise.reason).toBe("hard_security");
  });

  it("changes only presentation attention for a soft Review and never changes the engine decision", () => {
    const candidate = envelope({
      from: { displayName: "Acme Operations", address: "ops@unrelated.example", domain: "unrelated.example" },
      subject: "Routine notice from portal: acme.com",
      authentication: {
        spf: "pass",
        dkim: "pass",
        dmarc: "pass",
        arc: "none",
        providerTrust: "trusted",
      },
      textPreview: "Routine informational correspondence. No credential, payment, urgency, callback, installation, or transfer is requested.",
      links: [],
      threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    });
    const result = scan(candidate);
    expect(result.scored.verdict).toBe("review");

    const high = applyProtectionSensitivity(result, "high");
    const balanced = applyProtectionSensitivity(result, "balanced");
    const low = applyProtectionSensitivity(result, "low_noise");
    for (const decision of [high, balanced, low]) {
      expect(decision.verdict).toBe(result.scored.verdict);
      expect(decision.action).toBe(result.action);
      expect(decision.hardSecuritySignal).toBe(false);
    }
    expect(high.attention).toBe("alert");
    expect(balanced.attention).toBe("activity");
    expect(low.attention).toBe("none");
  });
});
