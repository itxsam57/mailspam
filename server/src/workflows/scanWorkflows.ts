import type { EmailAdapter, FolderDescriptor } from "../canonical/adapter.js";
import type { PersonalPolicyStore } from "../engine/layers/personalRules.js";
import type { ThreatFeedCache } from "../engine/layers/globalIntelligence.js";
import { scanMessage, type ScanResult } from "../engine/pipeline.js";

export interface ScanCounters {
  examined: number;
  safe: number;
  review: number;
  highRisk: number;
  confirmedThreat: number;
  unknown: number;
  skipped: number;
  malformed: number;
}

function emptyCounters(): ScanCounters {
  return { examined: 0, safe: 0, review: 0, highRisk: 0, confirmedThreat: 0, unknown: 0, skipped: 0, malformed: 0 };
}

function tally(counters: ScanCounters, result: ScanResult) {
  counters.examined++;
  if (result.envelope.parseStatus === "malformed") counters.malformed++;
  if (result.envelope.parseStatus === "skipped") counters.skipped++;
  switch (result.scored.verdict) {
    case "safe": counters.safe++; break;
    case "review": counters.review++; break;
    case "high_risk": counters.highRisk++; break;
    case "confirmed_threat": counters.confirmedThreat++; break;
    case "unknown": counters.unknown++; break;
  }
}

export interface ScanProgress {
  counters: ScanCounters;
  /** Only warning+ verdicts are ever included here — spec: never render individual safe messages. */
  suspiciousCards: ScanResult[];
  cursor: string | null;
  done: boolean;
}

export interface ScanDeps {
  personalPolicy: PersonalPolicyStore;
  threatFeed: ThreatFeedCache;
}

function isSuspicious(result: ScanResult): boolean {
  return result.scored.verdict !== "safe";
}

const DEFAULT_PAGE_SIZE = 50;

/**
 * Quick Scan (spec 8.1): newest bounded set of messages, one page, no
 * automatic live link visits, cancellable mid-fetch.
 */
export async function* quickScan(
  adapter: EmailAdapter,
  deps: ScanDeps,
  signal: AbortSignal,
  pageSize = DEFAULT_PAGE_SIZE
): AsyncGenerator<ScanProgress> {
  await adapter.connect(signal);
  try {
    const folders = await adapter.listFolders(signal);
    const inbox = folders.find((f) => f.normalized === "inbox");
    if (!inbox) return;

    const counters = emptyCounters();
    const page = await adapter.fetchPage(inbox, null, pageSize, signal);
    const suspiciousCards: ScanResult[] = [];

    for (const envelope of page.envelopes) {
      if (signal.aborted) return;
      const result = scanMessage(envelope, deps);
      tally(counters, result);
      if (isSuspicious(result)) suspiciousCards.push(result);
    }

    yield { counters, suspiciousCards, cursor: page.nextCursor, done: true };
  } finally {
    await adapter.disconnect();
  }
}

/**
 * Full Mailbox Audit (spec 8.2): discovers folders lazily, excludes
 * Sent/Drafts/Trash by default, pages through everything with a resumable
 * cursor per folder, deduplicating by messageId across folders/labels,
 * yielding incremental progress after every page rather than blocking on
 * a full pre-count.
 */
export async function* fullMailboxAudit(
  adapter: EmailAdapter,
  deps: ScanDeps,
  signal: AbortSignal,
  opts: { includeExcludedFolders?: boolean; pageSize?: number; resumeCursors?: Record<string, string | null> } = {}
): AsyncGenerator<ScanProgress & { folder: string }> {
  const pageSize = opts.pageSize ?? DEFAULT_PAGE_SIZE;
  await adapter.connect(signal);
  const seenMessageIds = new Set<string>();
  const counters = emptyCounters();

  try {
    const allFolders = await adapter.listFolders(signal);
    const targetFolders: FolderDescriptor[] = opts.includeExcludedFolders
      ? allFolders
      : allFolders.filter((f) => f.includedByDefault);

    for (const folder of targetFolders) {
      let cursor: string | null = opts.resumeCursors?.[folder.providerFolderName] ?? null;
      let done = false;

      while (!done) {
        if (signal.aborted) return;
        const page = await adapter.fetchPage(folder, cursor, pageSize, signal);
        const suspiciousCards: ScanResult[] = [];

        for (const envelope of page.envelopes) {
          if (signal.aborted) return;
          if (seenMessageIds.has(envelope.messageId)) continue; // cross-folder/label dedup
          seenMessageIds.add(envelope.messageId);
          const result = scanMessage(envelope, deps);
          tally(counters, result);
          if (isSuspicious(result)) suspiciousCards.push(result);
        }

        cursor = page.nextCursor;
        done = page.done;
        yield { counters: { ...counters }, suspiciousCards, cursor, done: done && folder === targetFolders[targetFolders.length - 1], folder: folder.providerFolderName };
      }
    }
  } finally {
    await adapter.disconnect();
  }
}

/**
 * Spam/Junk Scan (spec 8.3): only the Spam/Junk folder, same complete
 * engine as Inbox (never a weaker pass), batched fetch per page, never
 * renders every safe Junk message.
 */
export async function* spamJunkScan(
  adapter: EmailAdapter,
  deps: ScanDeps,
  signal: AbortSignal,
  pageSize = DEFAULT_PAGE_SIZE
): AsyncGenerator<ScanProgress> {
  await adapter.connect(signal);
  try {
    const folders = await adapter.listFolders(signal);
    const spam = folders.find((f) => f.normalized === "spam");
    if (!spam) return;

    const counters = emptyCounters();
    let cursor: string | null = null;
    let done = false;

    while (!done) {
      if (signal.aborted) return;
      const page = await adapter.fetchPage(spam, cursor, pageSize, signal);
      const suspiciousCards: ScanResult[] = [];

      for (const envelope of page.envelopes) {
        if (signal.aborted) return;
        const result = scanMessage(envelope, deps);
        tally(counters, result);
        if (isSuspicious(result)) suspiciousCards.push(result);
      }

      cursor = page.nextCursor;
      done = page.done;
      yield { counters: { ...counters }, suspiciousCards, cursor, done };
    }
  } finally {
    await adapter.disconnect();
  }
}

/**
 * Stop Scan (spec 8.4). Scan workflows above already check `signal.aborted`
 * before every provider call and after every message, so the caller only
 * needs to call AbortController.abort() — cancellation propagates through
 * adapter.fetchPage()'s own signal checks and to the adapter's live
 * sockets (each adapter's implementation is responsible for rejecting
 * pending commands and never writing to a destroyed transport; see the
 * imap adapter for the concrete case).
 */
export function createStoppableScan() {
  const controller = new AbortController();
  return {
    signal: controller.signal,
    stop: () => controller.abort(),
  };
}
