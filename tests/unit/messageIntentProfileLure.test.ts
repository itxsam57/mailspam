import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { messageIntentLayer } from "../../server/src/engine/layers/messageIntent.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  return {
    provider: "icloud",
    accountProof: "proof",
    messageId: "message-id",
    providerNativeId: "native-id",
    folder: "spam",
    providerFolderName: "Junk",
    from: { displayName: "Danielle Peterson", address: "walkevirginia597@gmail.com", domain: "gmail.com" },
    replyTo: null,
    subject: "",
    date: new Date(0).toISOString(),
    authentication: { spf: "unknown", dkim: "unknown", dmarc: "unknown", arc: "unknown" },
    textPreview: "Let's meet. I'm waiting for you.",
    htmlSignals: {
      extractedText: "Let's meet. View My Profile. I'm Waiting for You.",
      hrefs: ["https://redirect.example/profile"],
      hasForm: false,
      hasPasswordField: false,
    },
    links: [
      {
        visibleText: "View My Profile",
        rawUrl: "https://redirect.example/profile",
        normalizedUrl: "https://redirect.example/profile",
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
      sizeBytes: 500,
      encoding: "multipart",
      contentCoverage: "complete",
    },
    ...overrides,
  };
}

const threatFeed = { getVerifiedEntries: () => [] };

describe("romance lure risk ladder", () => {
  it("escalates a first-contact romance profile redirect to High Risk", () => {
    const message = envelope();
    const layer = messageIntentLayer(message);
    expect(layer.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "PROFILE_LURE_REDIRECT", scoreContribution: 3 }),
      expect.objectContaining({ code: "HIGH_CONFIDENCE_ROMANCE_LURE", scoreContribution: 3 }),
    ]));
    const result = scanMessage(message, {
      personalPolicy: new InMemoryPersonalPolicyStore(),
      threatFeed,
    });
    expect(result.scored.score).toBeGreaterThanOrEqual(6);
    expect(result.scored.verdict).toBe("high_risk");
  });

  it("escalates a private-photo lure even when no external link was parsed", () => {
    const message = envelope({
      subject: "Wanna see photos me",
      textPreview: "Wanna see my private photos?",
      htmlSignals: null,
      links: [],
    });
    const result = scanMessage(message, {
      personalPolicy: new InMemoryPersonalPolicyStore(),
      threatFeed,
    });
    expect(result.scored.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "UNSOLICITED_ROMANCE_LURE" }),
      expect.objectContaining({ code: "HIGH_CONFIDENCE_ROMANCE_LURE" }),
    ]));
    expect(result.scored.verdict).toBe("high_risk");
  });

  it("keeps an ambiguous first-contact social introduction at Review", () => {
    const message = envelope({
      subject: "I like to meet new people",
      textPreview: "Hello, I like to meet new people.",
      htmlSignals: null,
      links: [],
    });
    const result = scanMessage(message, {
      personalPolicy: new InMemoryPersonalPolicyStore(),
      threatFeed,
    });
    expect(result.scored.evidence).toContainEqual(expect.objectContaining({
      code: "UNSOLICITED_ROMANCE_LURE",
      scoreContribution: 2,
    }));
    expect(result.scored.evidence.some((item) => item.code === "HIGH_CONFIDENCE_ROMANCE_LURE")).toBe(false);
    expect(result.scored.verdict).toBe("review");
  });

  it("does not flag an ordinary professional profile link", () => {
    const result = messageIntentLayer(envelope({
      subject: "My professional profile",
      textPreview: "You can view my profile and work history here.",
      htmlSignals: {
        extractedText: "View my profile and work history",
        hrefs: ["https://professional.example/profile"],
        hasForm: false,
        hasPasswordField: false,
      },
      links: [{
        visibleText: "View my profile",
        rawUrl: "https://professional.example/profile",
        normalizedUrl: "https://professional.example/profile",
        claimedBrand: null,
        brandDomainMismatch: null,
      }],
    }));
    expect(result.evidence.some((item) => item.code === "PROFILE_LURE_REDIRECT")).toBe(false);
    expect(result.evidence.some((item) => item.code === "HIGH_CONFIDENCE_ROMANCE_LURE")).toBe(false);
  });

  it("does not escalate non-first-contact romance language", () => {
    const result = messageIntentLayer(envelope({
      subject: "Wanna see photos me",
      links: [],
      htmlSignals: null,
      textPreview: "Wanna see my private photos?",
      threadContext: { isFirstContact: false, threadContinuityBroken: false, replyToChangedMidThread: false },
    }));
    expect(result.evidence.some((item) => item.code === "HIGH_CONFIDENCE_ROMANCE_LURE")).toBe(false);
  });
});
