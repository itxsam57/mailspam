import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { identityImpersonationLayer } from "../../server/src/engine/layers/identityImpersonation.js";

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  const base: CanonicalEnvelope = {
    provider: "gmail",
    accountProof: "governor-live-identity-account",
    messageId: "<governor-live-identity@example.test>",
    providerNativeId: "governor-live-identity-native",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: {
      displayName: "Google Accounts",
      address: "no-reply@accounts.google.com",
      domain: "accounts.google.com",
    },
    replyTo: null,
    subject: "Security alert for webrefreshlab@gmail.com",
    date: "2026-08-26T10:00:00.000Z",
    authentication: {
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      arc: "none",
      providerTrust: "trusted",
      rawHeader: "mx.receiver.example; spf=pass smtp.mailfrom=google.com; dkim=pass header.d=google.com header.s=s1; dmarc=pass header.from=google.com",
    },
    textPreview: "A routine authenticated account security notification.",
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: {
      isFirstContact: false,
      threadContinuityBroken: false,
      replyToChangedMidThread: false,
      relationshipPriorMessages: 4,
      relationshipPriorAuthenticatedMessages: 4,
      relationshipPriorSafeMessages: 4,
      relationshipPriorSuspiciousMessages: 0,
      hasEstablishedSenderHistory: true,
      relationshipAuthenticationDowngrade: false,
      replyToChangedFromRelationshipHistory: false,
    },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: {
      fetchedAt: "2026-08-26T10:00:00.000Z",
      sizeBytes: 640,
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

describe("Governor live identity-domain regression", () => {
  it("does not treat a recipient email address in the subject as a sender organization-domain claim", () => {
    const result = identityImpersonationLayer(envelope());

    expect(result.evidence).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "EXPLICIT_DOMAIN_CLAIM_MISMATCH" }),
    ]));
  });

  it("still treats an explicit portal-domain statement as an organization-domain claim", () => {
    const result = identityImpersonationLayer(envelope({
      from: {
        displayName: "Example Security",
        address: "security@unrelated.example",
        domain: "unrelated.example",
      },
      subject: "Security alert — portal: acme.com",
      authentication: {
        spf: "pass",
        dkim: "pass",
        dmarc: "pass",
        arc: "none",
        providerTrust: "trusted",
        rawHeader: "mx.receiver.example; spf=pass smtp.mailfrom=unrelated.example; dkim=pass header.d=unrelated.example header.s=s1; dmarc=pass header.from=unrelated.example",
      },
    }));

    expect(result.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({
        code: "EXPLICIT_DOMAIN_CLAIM_MISMATCH",
        scoreContribution: 4,
      }),
    ]));
  });

  it("still treats an email-domain claim in the sender display identity as explicit", () => {
    const result = identityImpersonationLayer(envelope({
      from: {
        displayName: "Billing support@cobalt-bank.example",
        address: "notice@unrelated-sender.example",
        domain: "unrelated-sender.example",
      },
      subject: "Account payment alert",
      authentication: {
        spf: "pass",
        dkim: "pass",
        dmarc: "pass",
        arc: "none",
        providerTrust: "trusted",
        rawHeader: "mx.receiver.example; spf=pass smtp.mailfrom=unrelated-sender.example; dkim=pass header.d=unrelated-sender.example header.s=s1; dmarc=pass header.from=unrelated-sender.example",
      },
    }));

    expect(result.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({
        code: "EXPLICIT_DOMAIN_CLAIM_MISMATCH",
        scoreContribution: 4,
      }),
    ]));
  });

  it("still treats an HTTPS URL host with userinfo syntax as an explicit domain claim", () => {
    const result = identityImpersonationLayer(envelope({
      from: {
        displayName: "Example Security",
        address: "security@unrelated.example",
        domain: "unrelated.example",
      },
      subject: "Review https://user@cobalt-bank.example/secure",
      authentication: {
        spf: "pass",
        dkim: "pass",
        dmarc: "pass",
        arc: "none",
        providerTrust: "trusted",
        rawHeader: "mx.receiver.example; spf=pass smtp.mailfrom=unrelated.example; dkim=pass header.d=unrelated.example header.s=s1; dmarc=pass header.from=unrelated.example",
      },
    }));

    expect(result.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({
        code: "EXPLICIT_DOMAIN_CLAIM_MISMATCH",
        scoreContribution: 4,
      }),
    ]));
  });
});
