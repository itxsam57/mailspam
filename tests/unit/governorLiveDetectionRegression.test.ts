import { describe, expect, test } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { identityImpersonationLayer } from "../../server/src/engine/layers/identityImpersonation.js";

function envelopeWithSubject(subject: string): CanonicalEnvelope {
  return {
    provider: "gmail",
    providerNativeId: "gov-google-security-alert-1",
    messageId: "<gov-google-security-alert-1@example.invalid>",
    subject,
    from: {
      displayName: "Google",
      address: "no-reply@accounts.google.com",
      domain: "accounts.google.com",
    },
    replyTo: null,
    to: [],
    cc: [],
    date: null,
    folder: "inbox",
    providerFolderName: "INBOX",
    textPreview: "A security event was detected for your Google Account.",
    htmlPreview: null,
    links: [],
    attachments: [],
    authentication: {
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      arc: "unknown",
      rawHeader: "spf=pass smtp.mailfrom=accounts.google.com; dkim=pass header.d=accounts.google.com; dmarc=pass header.from=google.com",
      providerTrust: "trusted",
    },
    listHeaders: {
      listId: null,
      listUnsubscribe: null,
      listUnsubscribePost: null,
    },
    threadContext: {
      senderPreviouslySeenInScan: false,
      establishedRelationship: false,
      firstContact: true,
      knownThreadReference: false,
      replyToStable: true,
    },
    diagnostics: {
      contentCoverage: "complete",
    },
    parseStatus: "complete",
    parseNotes: [],
  } as CanonicalEnvelope;
}

describe("Governor live detection regressions", () => {
  test("recipient email domain in subject is not treated as an asserted sender-domain claim", () => {
    const result = identityImpersonationLayer(
      envelopeWithSubject("Security alert for webrefreshlab@gmail.com"),
    );

    expect(result.evidence.map((item) => item.code)).not.toContain("EXPLICIT_DOMAIN_CLAIM_MISMATCH");
  });
});
