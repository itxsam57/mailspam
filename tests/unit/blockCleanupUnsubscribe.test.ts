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
import {
  executeOneClickUnsubscribe,
  isPublicNetworkAddress,
  normalizeOneClickTarget,
  unsubscribeCapability,
} from "../../server/src/workflows/unsubscribe.js";
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
    const capability = unsubscribeCapability(envelope);
    expect(capability.method).toBe("one_click_post");
    expect(capability.target).toBe("https://realnewsco.com/unsubscribe?one-click=true");
  });

  it("does not auto-invoke a bare List-Unsubscribe link", async () => {
    const raw = readFileSync(join(CORPUS_DIR, "newsletter_marketing_abuse/malicious-plain.eml"), "utf-8");
    const envelope = await normalizeRawMessage(raw, { provider: "gmail", accountProof: "x", providerFolderName: "INBOX", normalizedFolder: "inbox", providerNativeId: "test-id" });
    const capability = unsubscribeCapability(envelope);
    expect(capability.method).toBe("link_only");
  });

  it("accepts only credential-free standard-port HTTPS one-click targets", () => {
    expect(normalizeOneClickTarget(" https://example.test/unsub#fragment ")).toBe("https://example.test/unsub");
    expect(() => normalizeOneClickTarget("http://example.test/unsub")).toThrow("requires HTTPS");
    expect(() => normalizeOneClickTarget("https://user:secret@example.test/unsub")).toThrow("must not contain credentials");
    expect(() => normalizeOneClickTarget("https://example.test:8443/unsub")).toThrow("standard HTTPS port");
    expect(() => normalizeOneClickTarget("https://localhost/unsub")).toThrow("host is not allowed");
  });

  it("rejects private, loopback, link-local, and mapped network addresses", () => {
    expect(isPublicNetworkAddress("8.8.8.8")).toBe(true);
    expect(isPublicNetworkAddress("2606:4700:4700::1111")).toBe(true);
    expect(isPublicNetworkAddress("127.0.0.1")).toBe(false);
    expect(isPublicNetworkAddress("10.1.2.3")).toBe(false);
    expect(isPublicNetworkAddress("169.254.169.254")).toBe(false);
    expect(isPublicNetworkAddress("192.168.1.5")).toBe(false);
    expect(isPublicNetworkAddress("::1")).toBe(false);
    expect(isPublicNetworkAddress("fd00::1")).toBe(false);
    expect(isPublicNetworkAddress("::ffff:127.0.0.1")).toBe(false);
  });

  it("passes only the normalized target to the injected POST and trusts only 2xx", async () => {
    const calls: string[] = [];
    const ok = await executeOneClickUnsubscribe("https://example.test/unsub#ignored", async (url) => {
      calls.push(url);
      return { status: 204 };
    });
    expect(calls).toEqual(["https://example.test/unsub"]);
    expect(ok).toEqual({ success: true, status: 204, reason: undefined });

    const fail = await executeOneClickUnsubscribe("https://example.test/unsub", async () => ({ status: 302 }));
    expect(fail.success).toBe(false);
    expect(fail.reason).toContain("HTTP 302");
  });

  it("returns a visible reason for invalid targets and network failures", async () => {
    const invalid = await executeOneClickUnsubscribe("http://localhost/unsub", async () => ({ status: 200 }));
    expect(invalid.success).toBe(false);
    expect(invalid.reason).toContain("requires HTTPS");

    const failed = await executeOneClickUnsubscribe("https://example.test/unsub", async () => {
      throw new Error("connection reset");
    });
    expect(failed).toEqual({ success: false, reason: "connection reset" });
  });
});
