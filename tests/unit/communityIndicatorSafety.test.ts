import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { buildCommunityReportContext } from "../../server/src/community/fingerprint.js";
import type { ScoredMessage } from "../../server/src/engine/verdict.js";

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  return {
    provider: "gmail",
    accountProof: "private-account-proof",
    messageId: "message-id",
    providerNativeId: "provider-id",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: {
      displayName: "Hosted report",
      address: "looker-studio-noreply@google.com",
      domain: "google.com",
    },
    replyTo: {
      displayName: "Campaign",
      address: "reply@campaign-control.example",
      domain: "campaign-control.example",
    },
    subject: "Join our exclusive adult community",
    date: new Date().toISOString(),
    authentication: { spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview: "Open the campaign.",
    htmlSignals: null,
    links: [{
      visibleText: "Open",
      rawUrl: "https://destination-scam.example/open",
      normalizedUrl: "https://destination-scam.example/open",
      claimedBrand: null,
      brandDomainMismatch: null,
    }],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: { fetchedAt: new Date().toISOString(), sizeBytes: 1000, encoding: "multipart", contentCoverage: "complete" },
    ...overrides,
  };
}

function scored(extraEvidence: ScoredMessage["evidence"] = []): ScoredMessage {
  return {
    score: 8,
    verdict: "high_risk",
    confirmedByRule: false,
    layerResults: [],
    evidence: [
      { layer: "message_intent", code: "UNSOLICITED_ADULT_SITE_CAMPAIGN", description: "campaign", scoreContribution: 4, source: "local" },
      { layer: "identity_impersonation", code: "REPLY_TO_MISMATCH", description: "reply", scoreContribution: 2, source: "local" },
      ...extraEvidence,
    ],
  };
}

describe("community indicator shared-infrastructure safety", () => {
  it("does not publish product-prefixed no-reply delivery addresses as malicious senders", () => {
    const context = buildCommunityReportContext(envelope(), scored());
    expect(context.indicators).not.toContainEqual({
      type: "sender",
      value: "looker-studio-noreply@google.com",
    });
    expect(context.indicators).toContainEqual({
      type: "reply_to_domain",
      value: "campaign-control.example",
    });
    expect(context.indicators).toContainEqual({
      type: "url_domain",
      value: "destination-scam.example",
    });
  });

  it("does not publish a shared consumer mailbox domain as a malicious Reply-To domain", () => {
    const context = buildCommunityReportContext(envelope({
      replyTo: {
        displayName: "Personal reply",
        address: "attacker@gmail.com",
        domain: "gmail.com",
      },
    }), scored());
    expect(context.indicators.some((item) => item.type === "reply_to_domain")).toBe(false);
    expect(context.indicators.some((item) => item.type === "campaign")).toBe(true);
  });

  it("suppresses a broad destination-domain indicator when the detector identifies shared URL-shortener infrastructure", () => {
    const context = buildCommunityReportContext(envelope({
      links: [{
        visibleText: "Open",
        rawUrl: "https://short.example/abc",
        normalizedUrl: "https://short.example/abc",
        claimedBrand: null,
        brandDomainMismatch: null,
      }],
    }), scored([{
      layer: "link_structure",
      code: "URL_SHORTENER",
      description: "shared shortener",
      scoreContribution: 1,
      source: "local",
    }]));
    expect(context.indicators.some((item) => item.type === "url_domain")).toBe(false);
    expect(context.indicators.some((item) => item.type === "campaign")).toBe(true);
  });

  it("still publishes a direct non-generic sender address", () => {
    const context = buildCommunityReportContext(envelope({
      from: {
        displayName: "Direct sender",
        address: "scammer@direct-scam.example",
        domain: "direct-scam.example",
      },
    }), scored());
    expect(context.indicators).toContainEqual({
      type: "sender",
      value: "scammer@direct-scam.example",
    });
  });
});
