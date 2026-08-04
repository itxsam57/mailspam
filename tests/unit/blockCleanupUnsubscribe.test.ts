import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { normalizeRawMessage } from "../../server/src/util/mimeNormalize.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { blockSender, blockDomain, moveMessagesToTrash } from "../../server/src/workflows/blockAndCleanup.js";
import { unsubscribeCapability, executeOneClickUnsubscribe } from "../../server/src/workflows/unsubscribe.js";
import type { EmailAdapter, FetchPage, FolderDescriptor } from "../../server/src/canonical/adapter.js";
import type { Provider } from "../../server/src/canonical/envelope.js";

const CORPUS_DIR = join(import.meta.dirname, "../../fixtures/scam-corpus");

describe("block and cleanup", () => {
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

  it("moveMessagesToTrash batches into a single adapter call, not one per message", async () => {
    let callCount = 0;
    let lastBatchSize = 0;
    const adapter: Pick<EmailAdapter, "moveToTrash"> = {
      async moveToTrash(ids: string[]) { callCount++; lastBatchSize = ids.length; },
    };
    const result = await moveMessagesToTrash(adapter as EmailAdapter, ["a", "b", "c"], new AbortController().signal);
    expect(callCount).toBe(1);
    expect(lastBatchSize).toBe(3);
    expect(result.moved).toBe(3);
    expect(result.failed).toEqual([]);
  });

  it("reports failures per-message without throwing when the adapter call fails", async () => {
    const adapter: Pick<EmailAdapter, "moveToTrash"> = {
      async moveToTrash() { throw new Error("provider unavailable"); },
    };
    const result = await moveMessagesToTrash(adapter as EmailAdapter, ["a", "b"], new AbortController().signal);
    expect(result.moved).toBe(0);
    expect(result.failed).toHaveLength(2);
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
