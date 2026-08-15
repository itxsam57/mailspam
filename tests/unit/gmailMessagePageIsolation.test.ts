import { describe, expect, it } from "vitest";
import { resolveGmailPageMessages } from "../../server/src/adapters/gmail/gmailAdapter.js";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";

function envelope(id: string, parseStatus: CanonicalEnvelope["parseStatus"] = "complete"): CanonicalEnvelope {
  const inaccessible = parseStatus !== "complete";
  return {
    provider: "gmail",
    accountProof: "gmail-account-proof",
    messageId: `message-${id}`,
    providerNativeId: id,
    folder: "inbox",
    providerFolderName: "INBOX",
    from: inaccessible
      ? { displayName: null, address: null, domain: null }
      : { displayName: "Sender", address: "sender@example.test", domain: "example.test" },
    replyTo: null,
    subject: inaccessible ? "" : "Routine message",
    date: new Date(0).toISOString(),
    authentication: { spf: "unknown", dkim: "unknown", dmarc: "unknown", arc: "unknown" },
    textPreview: inaccessible ? null : "Routine readable message content.",
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus,
    parseNotes: inaccessible ? ["Gmail message content could not be inspected safely."] : [],
    diagnostics: {
      fetchedAt: new Date(0).toISOString(),
      sizeBytes: inaccessible ? 0 : 64,
      encoding: inaccessible ? "unknown" : "plain",
      contentCoverage: inaccessible ? "insufficient" : "complete",
    },
  };
}

const inaccessible = (id: string) => envelope(id, "inaccessible");

function controller() {
  return new AbortController();
}

describe("Gmail page message isolation", () => {
  it("keeps one unreadable Gmail message from collapsing the rest of the page", async () => {
    const abort = controller();
    const result = await resolveGmailPageMessages({
      ids: ["good-1", "unreadable", "good-2"],
      signal: abort.signal,
      concurrency: 2,
      readRawMessage: async (id) => {
        if (id === "unreadable") throw new Error("provider message read failed");
        return Buffer.from(id, "utf8");
      },
      normalizeMessage: async (_raw, id) => envelope(id),
      inaccessibleMessage: inaccessible,
    });

    expect(result.map((item) => item.providerNativeId)).toEqual(["good-1", "unreadable", "good-2"]);
    expect(result.map((item) => item.parseStatus)).toEqual(["complete", "inaccessible", "complete"]);
  });

  it("converts a local normalization failure to inaccessible instead of failing the Gmail page", async () => {
    const abort = controller();
    const result = await resolveGmailPageMessages({
      ids: ["normalization-failure"],
      signal: abort.signal,
      readRawMessage: async () => Buffer.from("raw-message", "utf8"),
      normalizeMessage: async () => { throw new Error("local MIME inspection failed"); },
      inaccessibleMessage: inaccessible,
    });

    expect(result).toHaveLength(1);
    expect(result[0]!.parseStatus).toBe("inaccessible");
    const scored = scanMessage(result[0]!, {
      personalPolicy: new InMemoryPersonalPolicyStore(),
      threatFeed: { getVerifiedEntries: () => [] },
    });
    expect(scored.scored.verdict).toBe("unknown");
    expect(scored.action).toBe("none");
  });

  it("keeps an empty raw provider response fail-closed as inaccessible", async () => {
    const abort = controller();
    const result = await resolveGmailPageMessages({
      ids: ["empty-raw"],
      signal: abort.signal,
      readRawMessage: async () => null,
      normalizeMessage: async (_raw, id) => envelope(id),
      inaccessibleMessage: inaccessible,
    });

    expect(result[0]!.parseStatus).toBe("inaccessible");
    expect(result[0]!.diagnostics.contentCoverage).toBe("insufficient");
  });

  it("still fails when Gmail cannot read any listed message in the page", async () => {
    const abort = controller();
    await expect(resolveGmailPageMessages({
      ids: ["provider-failure-1", "provider-failure-2"],
      signal: abort.signal,
      readRawMessage: async () => { throw new Error("provider unavailable"); },
      normalizeMessage: async (_raw, id) => envelope(id),
      inaccessibleMessage: inaccessible,
    })).rejects.toThrow("Gmail could not read any messages in the selected page.");
  });

  it("preserves cancellation rather than converting it to an inaccessible message", async () => {
    const abort = controller();
    abort.abort();
    await expect(resolveGmailPageMessages({
      ids: ["cancelled"],
      signal: abort.signal,
      readRawMessage: async () => Buffer.from("raw", "utf8"),
      normalizeMessage: async (_raw, id) => envelope(id),
      inaccessibleMessage: inaccessible,
    })).rejects.toMatchObject({ name: "AbortError" });
  });
});
