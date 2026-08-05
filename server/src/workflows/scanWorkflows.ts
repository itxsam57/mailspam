import type { EmailAdapter, FolderDescriptor } from "../canonical/adapter.js";
import type { NormalizedFolder, ParseStatus } from "../canonical/envelope.js";
import type { Verdict } from "../engine/verdict.js";
import type { PersonalPolicyStore } from "../engine/layers/personalRules.js";
import type { ThreatFeedCache } from "../engine/layers/globalIntelligence.js";
import { scanMessage, type ScanResult } from "../engine/pipeline.js";
import { messageExceptionKey } from "./messageReview.js";
import { unsubscribeCapability, type UnsubscribeCapability } from "./unsubscribe.js";

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

export interface ScanActionContext {
  providerNativeId: string;
  messageId: string;
  exceptionKey: string;
  senderAddress: string | null;
  normalizedFolder: NormalizedFolder;
  unsubscribe: UnsubscribeCapability;
}

export interface ScanDiagnosticSummary {
  subject: string;
  fromAddress: string | null;
  fromDomain: string | null;
  folder: string;
  verdict: Verdict;
  score: number;
  parseStatus: ParseStatus;
  parseNotes: string[];
  evidenceCodes: string[];
  /** Server-only until converted into opaque action tokens. */
  actionContext: ScanActionContext;
  /** Added by the API server after action-token registration. */
  reviewAction?: unknown;
  unsubscribeAction?: unknown;
}

function diagnosticSummary(result: ScanResult): ScanDiagnosticSummary {
  return {
    subject: result.envelope.subject || "(no subject)",
    fromAddress: result.envelope.from.address,
    fromDomain: result.envelope.from.domain,
    folder: result.envelope.providerFolderName,
    verdict: result.scored.verdict,
    score: result.scored.score,
    parseStatus: result.envelope.parseStatus,
    parseNotes: [...result.envelope.parseNotes],
    evidenceCodes: result.scored.evidence
      .filter((item) => item.scoreContribution !== 0)
      .map((item) => item.code),
    actionContext: {
      providerNativeId: result.envelope.providerNativeId,
      messageId: result.envelope.messageId,
      exceptionKey: messageExceptionKey(result.envelope),
      senderAddress: result.envelope.from.address,
      normalizedFolder: result.envelope.folder,
      unsubscribe: unsubscribeCapability(result.envelope),
    },
  };
}

export interface ScanProgress {
  counters: ScanCounters;
  /** Only warning+ verdicts are included here; Safe stays in the compact audit. */
  suspiciousCards: ScanResult[];
  /** Privacy-reduced local audit plus opaque user-action tokens added by the API layer. */
  diagnosticSummaries: ScanDiagnosticSummary[];
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

export async function* quickScan(
  adapter: EmailAdapter,
  deps: ScanDeps,
  signal: AbortSignal,
  pageSize = DEFAULT_PAGE_SIZE,
): AsyncGenerator<ScanProgress> {
  await adapter.connect(signal);
  try {
    const folders = await adapter.listFolders(signal);
    const inbox = folders.find((folder) => folder.normalized === "inbox");
    if (!inbox) {
      throw new Error(`Inbox folder was not found. Discovered folders: ${folders.map((folder) => folder.providerFolderName).join(", ") || "none"}.`);
    }

    const counters = emptyCounters();
    const page = await adapter.fetchPage(inbox, null, pageSize, signal);
    const suspiciousCards: ScanResult[] = [];
    const diagnosticSummaries: ScanDiagnosticSummary[] = [];

    for (const envelope of page.envelopes) {
      if (signal.aborted) return;
      const result = scanMessage(envelope, deps);
      tally(counters, result);
      diagnosticSummaries.push(diagnosticSummary(result));
      if (isSuspicious(result)) suspiciousCards.push(result);
    }

    yield { counters, suspiciousCards, diagnosticSummaries, cursor: page.nextCursor, done: true };
  } finally {
    await adapter.disconnect();
  }
}

export async function* fullMailboxAudit(
  adapter: EmailAdapter,
  deps: ScanDeps,
  signal: AbortSignal,
  opts: { includeExcludedFolders?: boolean; pageSize?: number; resumeCursors?: Record<string, string | null> } = {},
): AsyncGenerator<ScanProgress & { folder: string }> {
  const pageSize = opts.pageSize ?? DEFAULT_PAGE_SIZE;
  await adapter.connect(signal);
  const seenMessageIds = new Set<string>();
  const counters = emptyCounters();

  try {
    const allFolders = await adapter.listFolders(signal);
    const targetFolders: FolderDescriptor[] = opts.includeExcludedFolders
      ? allFolders
      : allFolders.filter((folder) => folder.includedByDefault);
    if (targetFolders.length === 0) {
      throw new Error(`No eligible mailbox folders were found. Discovered folders: ${allFolders.map((folder) => folder.providerFolderName).join(", ") || "none"}.`);
    }

    for (const folder of targetFolders) {
      let cursor: string | null = opts.resumeCursors?.[folder.providerFolderName] ?? null;
      let done = false;

      while (!done) {
        if (signal.aborted) return;
        const page = await adapter.fetchPage(folder, cursor, pageSize, signal);
        const suspiciousCards: ScanResult[] = [];
        const diagnosticSummaries: ScanDiagnosticSummary[] = [];

        for (const envelope of page.envelopes) {
          if (signal.aborted) return;
          if (seenMessageIds.has(envelope.messageId)) continue;
          seenMessageIds.add(envelope.messageId);
          const result = scanMessage(envelope, deps);
          tally(counters, result);
          diagnosticSummaries.push(diagnosticSummary(result));
          if (isSuspicious(result)) suspiciousCards.push(result);
        }

        cursor = page.nextCursor;
        done = page.done;
        yield {
          counters: { ...counters },
          suspiciousCards,
          diagnosticSummaries,
          cursor,
          done: done && folder === targetFolders[targetFolders.length - 1],
          folder: folder.providerFolderName,
        };
      }
    }
  } finally {
    await adapter.disconnect();
  }
}

export async function* spamJunkScan(
  adapter: EmailAdapter,
  deps: ScanDeps,
  signal: AbortSignal,
  pageSize = DEFAULT_PAGE_SIZE,
): AsyncGenerator<ScanProgress> {
  await adapter.connect(signal);
  try {
    const folders = await adapter.listFolders(signal);
    const spam = folders.find((folder) => folder.normalized === "spam");
    if (!spam) {
      throw new Error(`Spam/Junk folder was not found. Discovered folders: ${folders.map((folder) => folder.providerFolderName).join(", ") || "none"}.`);
    }

    const counters = emptyCounters();
    let cursor: string | null = null;
    let done = false;

    while (!done) {
      if (signal.aborted) return;
      const page = await adapter.fetchPage(spam, cursor, pageSize, signal);
      const suspiciousCards: ScanResult[] = [];
      const diagnosticSummaries: ScanDiagnosticSummary[] = [];

      for (const envelope of page.envelopes) {
        if (signal.aborted) return;
        const result = scanMessage(envelope, deps);
        tally(counters, result);
        diagnosticSummaries.push(diagnosticSummary(result));
        if (isSuspicious(result)) suspiciousCards.push(result);
      }

      cursor = page.nextCursor;
      done = page.done;
      yield { counters: { ...counters }, suspiciousCards, diagnosticSummaries, cursor, done };
    }
  } finally {
    await adapter.disconnect();
  }
}

export function createStoppableScan() {
  const controller = new AbortController();
  return {
    signal: controller.signal,
    stop: () => controller.abort(),
  };
}
