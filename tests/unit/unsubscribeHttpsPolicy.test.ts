import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import {
  normalizeManualUnsubscribeTarget,
  unsubscribeCapability,
} from "../../server/src/workflows/unsubscribe.js";

function envelope(listUnsubscribe: string | null): CanonicalEnvelope {
  return {
    provider: "gmail",
    accountProof: "proof",
    messageId: "message-id",
    providerNativeId: "native-id",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Newsletter", address: "news@example.com", domain: "example.com" },
    replyTo: null,
    subject: "Newsletter",
    date: new Date(0).toISOString(),
    authentication: { providerTrust: "trusted", spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview: "Newsletter",
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: "list.example.com", listUnsubscribe, listUnsubscribePost: null },
    threadContext: { isFirstContact: false, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 100, encoding: "plain", contentCoverage: "complete" },
  };
}

describe("unsubscribe HTTPS policy", () => {
  it("never offers a plain-HTTP List-Unsubscribe web action", () => {
    expect(unsubscribeCapability(envelope("<http://campaign.example.com/unsubscribe?id=1>"))).toEqual({
      available: false,
      method: "none",
      target: null,
      source: "none",
    });
  });

  it("keeps HTTPS manual unsubscribe available", () => {
    expect(unsubscribeCapability(envelope("<https://campaign.example.com/unsubscribe?id=1>"))).toMatchObject({
      available: true,
      method: "link_only",
      source: "list_header",
    });
  });

  it("rejects manual HTTP and non-standard HTTPS ports at registration time", () => {
    expect(() => normalizeManualUnsubscribeTarget("link_only", "http://campaign.example.com/unsubscribe")).toThrow(/HTTPS/);
    expect(() => normalizeManualUnsubscribeTarget("link_only", "https://campaign.example.com:8443/unsubscribe")).toThrow(/standard HTTPS port/);
    expect(normalizeManualUnsubscribeTarget("link_only", "https://campaign.example.com/unsubscribe")).toBe("https://campaign.example.com/unsubscribe");
  });

  it("keeps mailto unsubscribe independent from web transport policy", () => {
    expect(normalizeManualUnsubscribeTarget("mailto", "mailto:remove@example.com?subject=unsubscribe")).toContain("mailto:remove@example.com");
  });
});
