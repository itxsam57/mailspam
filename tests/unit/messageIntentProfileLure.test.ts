import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { messageIntentLayer } from "../../server/src/engine/layers/messageIntent.js";

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
    diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 500, encoding: "multipart" },
    ...overrides,
  };
}

describe("profile lure intent", () => {
  it("flags romance context plus a linked profile action", () => {
    const result = messageIntentLayer(envelope());
    expect(result.evidence).toEqual([
      expect.objectContaining({
        code: "PROFILE_LURE_REDIRECT",
        scoreContribution: 3,
      }),
    ]);
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
  });

  it("does not flag romance language without an external profile link", () => {
    const result = messageIntentLayer(envelope({
      links: [],
      htmlSignals: null,
      textPreview: "Let's meet. I'm waiting for you.",
    }));
    expect(result.evidence.some((item) => item.code === "PROFILE_LURE_REDIRECT")).toBe(false);
  });
});
