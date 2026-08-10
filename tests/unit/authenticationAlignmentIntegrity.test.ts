import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import {
  alignedAuthenticationDomains,
  authenticationPassed,
  authenticatedSenderIdentityDomains,
  hasAuthenticatedOrganizationalIdentity,
} from "../../server/src/engine/identitySignals.js";
import { messageIntentLayer } from "../../server/src/engine/layers/messageIntent.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  const authentication = overrides.authentication
    ? { ...overrides.authentication, providerTrust: overrides.authentication.providerTrust ?? "trusted" as const }
    : { spf: "unknown" as const, dkim: "unknown" as const, dmarc: "unknown" as const, arc: "none" as const, providerTrust: "trusted" as const };

  return {
    provider: "gmail",
    accountProof: "proof",
    messageId: "message-id",
    providerNativeId: "native-id",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: {
      displayName: "Cobalt Bank Security",
      address: "security@alerts.cobalt-bank.example",
      domain: "alerts.cobalt-bank.example",
    },
    replyTo: null,
    subject: "Cobalt Bank account notice",
    date: new Date(0).toISOString(),
    authentication,
    textPreview: "Routine account information from the sender. ".repeat(5),
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: {
      fetchedAt: new Date(0).toISOString(),
      sizeBytes: 1000,
      encoding: "plain",
      contentCoverage: "complete",
    },
    ...overrides,
    authentication,
  };
}

const deps = () => ({
  personalPolicy: new InMemoryPersonalPolicyStore(),
  threatFeed: { getVerifiedEntries: () => [] },
});

describe("RFC5322.From authentication alignment after trusted provenance", () => {
  it("accepts DMARC pass because DMARC already requires an aligned authenticated identifier", () => {
    const message = envelope({
      authentication: { spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    });

    expect(authenticationPassed(message)).toBe(true);
    expect(alignedAuthenticationDomains(message)).toEqual(["cobalt-bank.example"]);
    expect(authenticatedSenderIdentityDomains(message)).toEqual(["cobalt-bank.example"]);
  });

  it("treats explicit DMARC failure as authoritative even if a raw SPF/DKIM property appears aligned", () => {
    const message = envelope({
      authentication: {
        spf: "pass",
        dkim: "pass",
        dmarc: "fail",
        arc: "none",
        rawHeader: "mx.receiver.example; spf=pass smtp.mailfrom=bounce@mailer.cobalt-bank.example; dkim=pass header.d=mailer.cobalt-bank.example; dmarc=fail header.from=cobalt-bank.example",
      },
    });

    expect(authenticationPassed(message)).toBe(false);
    expect(alignedAuthenticationDomains(message)).toEqual([]);
  });

  it("does not authenticate the visible From domain from an unrelated SPF pass", () => {
    const message = envelope({
      authentication: {
        spf: "pass",
        dkim: "fail",
        dmarc: "none",
        arc: "none",
        rawHeader: "mx.receiver.example; spf=pass smtp.mailfrom=attacker.example; dkim=fail header.d=attacker.example; dmarc=none header.from=cobalt-bank.example",
      },
    });

    expect(authenticationPassed(message)).toBe(false);
    expect(alignedAuthenticationDomains(message)).toEqual([]);
    expect(hasAuthenticatedOrganizationalIdentity(message)).toBe(false);
  });

  it("does not authenticate the visible From domain from an unrelated DKIM pass", () => {
    const message = envelope({
      authentication: {
        spf: "fail",
        dkim: "pass",
        dmarc: "none",
        arc: "none",
        rawHeader: "mx.receiver.example; dkim=pass header.d=delivery-attacker.example header.s=s1; spf=fail smtp.mailfrom=attacker.example; dmarc=none header.from=cobalt-bank.example",
      },
    });

    expect(authenticationPassed(message)).toBe(false);
    expect(authenticatedSenderIdentityDomains(message)).toEqual([]);
  });

  it("accepts an aligned DKIM pass when DMARC status is unavailable", () => {
    const message = envelope({
      authentication: {
        spf: "unknown",
        dkim: "pass",
        dmarc: "unknown",
        arc: "none",
        rawHeader: "mx.receiver.example; dkim=pass header.d=mailer.cobalt-bank.example header.s=mail2026",
      },
    });

    expect(authenticationPassed(message)).toBe(true);
    expect(alignedAuthenticationDomains(message)).toEqual(["cobalt-bank.example"]);
  });

  it("accepts an aligned SPF MAIL FROM pass when DMARC status is unavailable", () => {
    const message = envelope({
      authentication: {
        spf: "pass",
        dkim: "unknown",
        dmarc: "unknown",
        arc: "none",
        rawHeader: "mx.receiver.example; spf=pass smtp.mailfrom=bounce@mailer.cobalt-bank.example",
      },
    });

    expect(authenticationPassed(message)).toBe(true);
    expect(alignedAuthenticationDomains(message)).toEqual(["cobalt-bank.example"]);
  });

  it("requires the property belonging to the passing result rather than borrowing an identity from another result", () => {
    const message = envelope({
      authentication: {
        spf: "pass",
        dkim: "pass",
        dmarc: "none",
        arc: "none",
        rawHeader: "mx.receiver.example; spf=pass smtp.mailfrom=attacker.example; dkim=fail header.d=cobalt-bank.example; dkim=pass header.d=attacker.example",
      },
    });

    expect(authenticationPassed(message)).toBe(false);
  });

  it("keeps credential-phishing evidence when only an unrelated SPF identity passed", () => {
    const message = envelope({
      subject: "Cobalt Bank verify your account",
      textPreview: "Verify your account within 24 hours or your account will be suspended. Click here to confirm your identity.",
      authentication: {
        spf: "pass",
        dkim: "fail",
        dmarc: "none",
        arc: "none",
        rawHeader: "mx.receiver.example; spf=pass smtp.mailfrom=attacker.example; dkim=fail header.d=attacker.example",
      },
    });

    const result = messageIntentLayer(message);
    expect(result.evidence).toContainEqual(expect.objectContaining({
      code: "CREDENTIAL_PHISH_INTENT",
      scoreContribution: 3,
    }));
  });

  it("does not let unrelated SPF authentication unlock Safe for bounded partial content", () => {
    const message = envelope({
      subject: "Cobalt Bank monthly information",
      textPreview: "Account information and service updates are available in your secure dashboard. ".repeat(3),
      authentication: {
        spf: "pass",
        dkim: "unknown",
        dmarc: "unknown",
        arc: "none",
        rawHeader: "mx.receiver.example; spf=pass smtp.mailfrom=attacker.example",
      },
      parseStatus: "partial",
      parseNotes: ["Readable text was bounded to 24576 bytes."],
      diagnostics: {
        fetchedAt: new Date(0).toISOString(),
        sizeBytes: 60000,
        encoding: "multipart",
        contentCoverage: "bounded_sufficient",
      },
    });

    expect(scanMessage(message, deps()).scored.verdict).toBe("unknown");
  });

  it("still allows aligned SPF authentication to satisfy the bounded Safe prerequisite", () => {
    const message = envelope({
      subject: "Cobalt Bank monthly information",
      textPreview: "Account information and service updates are available in your secure dashboard. ".repeat(3),
      authentication: {
        spf: "pass",
        dkim: "unknown",
        dmarc: "unknown",
        arc: "none",
        rawHeader: "mx.receiver.example; spf=pass smtp.mailfrom=bounce@mailer.cobalt-bank.example",
      },
      parseStatus: "partial",
      parseNotes: ["Readable text was bounded to 24576 bytes."],
      diagnostics: {
        fetchedAt: new Date(0).toISOString(),
        sizeBytes: 60000,
        encoding: "multipart",
        contentCoverage: "bounded_sufficient",
      },
    });

    expect(scanMessage(message, deps()).scored.verdict).toBe("safe");
  });
});
