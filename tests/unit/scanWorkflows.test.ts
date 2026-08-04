import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { FixtureAdapter, type FixtureMessage } from "../../server/src/adapters/fixtures/fixtureAdapter.js";
import { quickScan, fullMailboxAudit, createStoppableScan } from "../../server/src/workflows/scanWorkflows.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import type { EmailAdapter, FetchPage, FolderDescriptor } from "../../server/src/canonical/adapter.js";
import type { Provider } from "../../server/src/canonical/envelope.js";

const CORPUS_DIR = join(import.meta.dirname, "../../fixtures/scam-corpus");
const deps = { personalPolicy: new InMemoryPersonalPolicyStore(), threatFeed: { getVerifiedEntries: () => [] } };

function loadEml(relPath: string): string {
  return readFileSync(join(CORPUS_DIR, relPath), "utf-8");
}

describe("quickScan", () => {
  it("only surfaces suspicious cards, never individual safe messages, and counts everything", async () => {
    const messages: FixtureMessage[] = [
      { id: "1", rawEml: loadEml("brand_impersonation/malicious-plain.eml"), folder: "inbox", providerFolderName: "INBOX" },
      { id: "2", rawEml: loadEml("brand_impersonation/legit-plain.eml"), folder: "inbox", providerFolderName: "INBOX" },
    ];
    const adapter = new FixtureAdapter("gmail", messages);
    const { signal } = createStoppableScan();

    const results = [];
    for await (const progress of quickScan(adapter, deps, signal)) results.push(progress);

    expect(results).toHaveLength(1);
    const final = results[0]!;
    expect(final.counters.examined).toBe(2);
    expect(final.suspiciousCards).toHaveLength(1); // only the malicious one
    expect(final.suspiciousCards[0]!.envelope.messageId).toBeDefined();
    expect(final.suspiciousCards.every((c) => c.scored.verdict !== "safe")).toBe(true);
  });
});

describe("fullMailboxAudit", () => {
  it("excludes Sent/Drafts/Trash by default and deduplicates messages seen across folders", async () => {
    const shared = loadEml("brand_impersonation/malicious-plain.eml");
    const messages: FixtureMessage[] = [
      { id: "1", rawEml: shared, folder: "inbox", providerFolderName: "INBOX" },
      { id: "1-dup", rawEml: shared, folder: "archive", providerFolderName: "Archive" }, // same Message-ID, different folder
      { id: "2", rawEml: loadEml("brand_impersonation/legit-plain.eml"), folder: "sent", providerFolderName: "Sent" },
    ];
    const adapter = new FixtureAdapter("gmail", messages);
    const { signal } = createStoppableScan();

    const progressEvents = [];
    for await (const p of fullMailboxAudit(adapter, deps, signal)) progressEvents.push(p);

    const last = progressEvents[progressEvents.length - 1]!;
    // Sent is excluded by default, and the duplicate Message-ID across inbox/archive counts once.
    expect(last.counters.examined).toBe(1);
  });

  it("returns incremental progress after every page rather than blocking on a full pre-count", async () => {
    const messages: FixtureMessage[] = Array.from({ length: 5 }, (_, i) => ({
      id: String(i),
      rawEml: loadEml("brand_impersonation/legit-plain.eml").replace("legit@paypal.com", `legit${i}@paypal.com`),
      folder: "inbox" as const,
      providerFolderName: "INBOX",
    }));
    const adapter = new FixtureAdapter("gmail", messages);
    const { signal } = createStoppableScan();

    const progressEvents = [];
    for await (const p of fullMailboxAudit(adapter, deps, signal, { pageSize: 2 })) progressEvents.push(p);

    // 5 messages at page size 2 => 3 pages => at least 3 progress events, not one final blob.
    expect(progressEvents.length).toBeGreaterThanOrEqual(3);
  });
});

describe("Stop Scan cancellation", () => {
  /** A deliberately slow adapter double that respects the abort signal, simulating real network latency. */
  class SlowAdapter implements EmailAdapter {
    readonly provider: Provider = "imap";
    private pageCount = 0;
    async connect(signal: AbortSignal) { if (signal.aborted) throw new DOMException("Aborted", "AbortError"); }
    async listFolders(_signal: AbortSignal): Promise<FolderDescriptor[]> {
      return [{ providerFolderName: "INBOX", normalized: "inbox", includedByDefault: true }];
    }
    async fetchPage(_folder: FolderDescriptor, _cursor: string | null, _pageSize: number, signal: AbortSignal): Promise<FetchPage> {
      this.pageCount++;
      await new Promise((resolve, reject) => {
        const t = setTimeout(resolve, 500);
        signal.addEventListener("abort", () => { clearTimeout(t); reject(new DOMException("Aborted", "AbortError")); });
      });
      return { envelopes: [], nextCursor: "next", done: false };
    }
    async moveToTrash() {}
    async disconnect() {}
    getPageCount() { return this.pageCount; }
  }

  it("stops actual in-flight work within 2 seconds of abort() being called", async () => {
    const adapter = new SlowAdapter();
    const { signal, stop } = createStoppableScan();

    const runner = (async () => {
      const events = [];
      try {
        for await (const p of fullMailboxAudit(adapter, deps, signal, { pageSize: 10 })) events.push(p);
      } catch {
        // AbortError from the in-flight fetchPage is expected and acceptable —
        // the workflow must not swallow it into a false "done" state.
      }
      return events;
    })();

    setTimeout(() => stop(), 50);
    const start = Date.now();
    await runner;
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(2000);
    expect(signal.aborted).toBe(true);
  });
});
