import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { normalizeRawMessage } from "../../server/src/util/mimeNormalize.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import {
  blockSender,
  blockDomain,
  moveMessagesToTrash,
  normalizeProviderNativeIds,
  normalizeSenderAddress,
  normalizeSenderDomain,
} from "../../server/src/workflows/blockAndCleanup.js";
import { unsubscribeCapability, executeOneClickUnsubscribe } from "../../server/src/workflows/unsubscribe.js";
import type { EmailAdapter } from "../../server/src/canonical/adapter.js";

const CORPUS_DIR = join(import.meta.dirname, "../../fixtures/scam-corpus");

describe("block and cleanup", () => {
  it("normalizes exact sender addresses and sender domains", () => {
    expect(normalizeSenderAddress("  User.Name@Example.COM ")).toBe("user.name@example.com");
    expect(normalizeSenderDomain(" @Example.COM. ")).toBe("example.com");
  });

  it("rejects malformed sender and domain block values", () => {
    expect(() => normalizeSenderAddress("not-an-email")).toThrow("valid sender email");
    expect(() => normalizeSenderAddress(123)).toThrow("must be a string");
    expect(() => normalizeSenderDomain("localhost")).toThrow("valid sender domain");
    expect(() => normalizeSenderDomain("bad domain.example")).toThrow("valid sender domain");
  });

  it("blockSender adds the exact sender address to the personal policy store", async () => {
    const raw = readFileSync(join(CORPUS_DIR, "brand_impersonation/malicious-plain.eml"), "utf-8");
    const envelope = await normalizeRawMessage(raw, { provider: "gmail", accountProof: "x", providerFolderName: "INBOX", normalizedFolder: "inbox", providerNativeId: "test-id" });
    const store = new InMemoryPersonalPolicyStore();
    blockSender(store, envelope);
    expect(store.isBlockedSender(envelope.from.address!)).toBe(true);
  });

  it("blockDomain blocks the whole domain, not just one address", async () => {
    const raw = readFileSync(join(CORPUS_DIR, "brand_impersonation/malicious-plain.eml"), "utf-8");
    const envelope = await normalizeRawMessage(raw, { provider: "gmail", accountProof: "x", providerFolderName: "INBOX", normalizedFolder: "inbox", providerNativeId: "test-id" });
    const store = new InMemoryPersonalPolicyStore();
    blockDomain(store, envelope);
    expect(store.isBlockedDomain(envelope.from.domain!)).toBe(true);
  });

  it("normalizes, deduplicates, and preserves the selected provider identifiers", () => {
    expect(normalizeProviderNativeIds([" selected-id ", "selected-id", "other-id"])).toEqual([
      "selected-id",
      "other-id",
    ]);
  });

  it("rejects empty, malformed, or oversized trash action requests", () => {
    expect(() => normalizeProviderNativeIds([])).toThrow("At least one");
    expect(() => normalizeProviderNativeIds([""])).toThrow("non-empty string");
    expect(() => normalizeProviderNativeIds("selected-id")).toThrow("must be an array");
    expect(() => normalizeProviderNativeIds(["a", "b"], 1)).toThrow("maximum of 1");
  });

  it("moves exactly one selected message in one adapter call", async () => {
    const calls: string[][] = [];
    const adapter: Pick<EmailAdapter, "moveToTrash"> = {
      async moveToTrash(ids: string[]) { calls.push([...ids]); },
    };

    const result = await moveMessagesToTrash(
      adapter as EmailAdapter,
      ["selected-native-id"],
      new AbortController().signal,
    );

    expect(calls).toEqual([["selected-native-id"]]);
    expect(result).toEqual({ requested: 1, moved: 1, failed: [] });
  });

  it("batches multiple unique messages into a single adapter call", async () => {
    let callCount = 0;
    let received: string[] = [];
    const adapter: Pick<EmailAdapter, "moveToTrash"> = {
      async moveToTrash(ids: string[]) { callCount++; received = [...ids]; },
    };
    const result = await moveMessagesToTrash(adapter as EmailAdapter, ["a", "b", "a"], new AbortController().signal);
    expect(callCount).toBe(1);
    expect(received).toEqual(["a", "b"]);
    expect(result.moved).toBe(2);
    expect(result.failed).toEqual([]);
  });

  it("reports failures per message without claiming a move", async () => {
    const adapter: Pick<EmailAdapter, "moveToTrash"> = {
      async moveToTrash() { throw new Error("provider unavailable"); },
    };
    const result = await moveMessagesToTrash(adapter as EmailAdapter, ["a", "b"], new AbortController().signal);
    expect(result.moved).toBe(0);
    expect(result.failed).toEqual([
      { messageId: "a", reason: "provider unavailable" },
      { messageId: "b", reason: "provider unavailable" },
    ]);
  });
});

describe("unsubscribe", () => {
  it("prefers RFC 8058 one-click POST over a bare link when both are present", async () => {
    const raw = readFileSync(join(CORPUS_DIR, "newsletter_marketing_abuse/legit-plain.eml"), "utf-8");
    const envelope = await normalizeRawMessage(raw, { provider: "gmail", accountProof: "x", providerFolderName: "INBOX", normalizedFolder: "inbox", providerNativeId: "test-id" });
    const cap = unsubscribeCapability(envelope);
    expect(cap.method).toBe("one_click_post");
    expect(cap.target).toBe("https://realnewsco.com/unsubscribe?one-click=true");
  });

  it("falls back to link_only when List-Unsubscribe-Post is absent or not one-click", async () => {
    const raw = readFileSync(join(CORPUS_DIR, "newsletter_marketing_abuse/malicious-plain.eml"), "utf-8");
    const envelope = await normalizeRawMessage(raw, { provider: "gmail", accountProof: "x", providerFolderName: "INBOX", normalizedFolder: "inbox", providerNativeId: "test-id" });
    const cap = unsubscribeCapability(envelope);
    expect(cap.method).toBe("link_only");
  });

  it("executeOneClickUnsubscribe reports success only on 2xx", async () => {
    const ok = await executeOneClickUnsubscribe("https://example.test/unsub", async () => ({ status: 200 }));
    expect(ok.success).toBe(true);
    const fail = await executeOneClickUnsubscribe("https://example.test/unsub", async () => ({ status: 500 }));
    expect(fail.success).toBe(false);
  });
});
