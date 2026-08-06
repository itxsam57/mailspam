import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { campaignFingerprint } from "../../server/src/community/fingerprint.js";

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  return {
    provider: "gmail",
    accountProof: "account-a",
    messageId: "message-a",
    providerNativeId: "native-a",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Campaign", address: "first@delivery-one.example", domain: "delivery-one.example" },
    replyTo: { displayName: "Reply", address: "reply@campaign-control.example", domain: "campaign-control.example" },
    subject: "Join our exclusive adult community 2026",
    date: new Date(0).toISOString(),
    authentication: { spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview: "Open the campaign link.",
    htmlSignals: null,
    links: [{
      visibleText: "Open",
      rawUrl: "https://redirect-campaign.example/path?id=one",
      normalizedUrl: "https://redirect-campaign.example/path?id=one",
      claimedBrand: null,
      brandDomainMismatch: null,
    }],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 900, encoding: "multipart", contentCoverage: "complete" },
    ...overrides,
  };
}

describe("campaign fingerprint rotation resistance", () => {
  it("matches the same downstream campaign after sender and provider rotation", () => {
    const first = envelope();
    const rotated = envelope({
      provider: "outlook",
      accountProof: "different-account",
      messageId: "different-message",
      providerNativeId: "different-native",
      from: { displayName: "Different carrier", address: "rotated@totally-different-delivery.example", domain: "totally-different-delivery.example" },
      subject: "Join our exclusive adult community 9999",
      links: [{
        visibleText: "Continue",
        rawUrl: "https://redirect-campaign.example/another/private/path?token=secret",
        normalizedUrl: "https://redirect-campaign.example/another/private/path?token=secret",
        claimedBrand: null,
        brandDomainMismatch: null,
      }],
    });
    expect(campaignFingerprint(rotated)).toBe(campaignFingerprint(first));
  });

  it("does not merge campaigns when stable downstream infrastructure changes", () => {
    const first = envelope();
    const unrelated = envelope({
      replyTo: { displayName: "Reply", address: "reply@different-control.example", domain: "different-control.example" },
      links: [{
        visibleText: "Open",
        rawUrl: "https://different-destination.example/open",
        normalizedUrl: "https://different-destination.example/open",
        claimedBrand: null,
        brandDomainMismatch: null,
      }],
    });
    expect(campaignFingerprint(unrelated)).not.toBe(campaignFingerprint(first));
  });

  it("uses sender organization only as a fallback when no downstream signal exists", () => {
    const first = envelope({ replyTo: null, links: [], attachments: [] });
    const sameDomain = envelope({
      replyTo: null,
      links: [],
      attachments: [],
      from: { displayName: "Other", address: "rotated@delivery-one.example", domain: "delivery-one.example" },
    });
    const otherDomain = envelope({
      replyTo: null,
      links: [],
      attachments: [],
      from: { displayName: "Other", address: "rotated@delivery-two.example", domain: "delivery-two.example" },
    });
    expect(campaignFingerprint(sameDomain)).toBe(campaignFingerprint(first));
    expect(campaignFingerprint(otherDomain)).not.toBe(campaignFingerprint(first));
  });
});
