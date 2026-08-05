import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { messageIntentLayer } from "../../server/src/engine/layers/messageIntent.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  return {
    provider: "outlook",
    accountProof: "adult-campaign-test-account",
    messageId: "adult-campaign-message",
    providerNativeId: "native-adult-campaign",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: {
      displayName: "Shared reporting service",
      address: "no-reply@reports.platform.example",
      domain: "reports.platform.example",
    },
    replyTo: {
      displayName: "Campaign reply",
      address: "reply@unrelated-campaign.example",
      domain: "unrelated-campaign.example",
    },
    subject: "Join Our Exclusive Adult Community",
    date: new Date(0).toISOString(),
    authentication: { spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview: "Join our exclusive adult community. Open the site to meet members.",
    htmlSignals: {
      extractedText: "Join our exclusive adult community. Open the site.",
      hrefs: ["https://redirect.example/join"],
      hasForm: false,
      hasPasswordField: false,
    },
    links: [{
      visibleText: "Join community",
      rawUrl: "https://redirect.example/join",
      normalizedUrl: "https://redirect.example/join",
      claimedBrand: null,
      brandDomainMismatch: null,
    }],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: {
      fetchedAt: new Date(0).toISOString(),
      sizeBytes: 1200,
      encoding: "multipart",
      contentCoverage: "complete",
    },
    ...overrides,
  };
}

const threatFeed = { getVerifiedEntries: () => [] };

describe("explicit unsolicited adult-site campaigns", () => {
  it("reaches High Risk when a first-contact adult solicitation links externally and redirects replies", () => {
    const message = envelope();
    const result = scanMessage(message, {
      personalPolicy: new InMemoryPersonalPolicyStore(),
      threatFeed,
    });

    expect(result.scored.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "REPLY_TO_MISMATCH", scoreContribution: 2 }),
      expect.objectContaining({ code: "UNSOLICITED_ADULT_SITE_CAMPAIGN", scoreContribution: 4 }),
    ]));
    expect(result.scored.score).toBeGreaterThanOrEqual(6);
    expect(result.scored.verdict).toBe("high_risk");
  });

  it("does not escalate an established subscribed adult-industry newsletter solely because of its topic", () => {
    const message = envelope({
      replyTo: {
        displayName: "Newsletter",
        address: "reply@reports.platform.example",
        domain: "reports.platform.example",
      },
      subject: "Adult industry policy newsletter",
      textPreview: "Your subscribed industry policy newsletter is ready.",
      htmlSignals: null,
      links: [],
      threadContext: { isFirstContact: false, threadContinuityBroken: false, replyToChangedMidThread: false },
    });
    const result = messageIntentLayer(message);
    expect(result.evidence.some((item) => item.code === "UNSOLICITED_ADULT_SITE_CAMPAIGN")).toBe(false);
  });

  it("does not use explicit adult wording alone without an external destination", () => {
    const message = envelope({ links: [], htmlSignals: null });
    const result = messageIntentLayer(message);
    expect(result.evidence.some((item) => item.code === "UNSOLICITED_ADULT_SITE_CAMPAIGN")).toBe(false);
  });

  it("does not use the campaign rule when Reply-To remains within the sender organization", () => {
    const message = envelope({
      replyTo: {
        displayName: "Campaign reply",
        address: "reply@mailer.reports.platform.example",
        domain: "mailer.reports.platform.example",
      },
    });
    const result = messageIntentLayer(message);
    expect(result.evidence.some((item) => item.code === "UNSOLICITED_ADULT_SITE_CAMPAIGN")).toBe(false);
  });
});
