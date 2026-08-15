import { createHash } from "node:crypto";
import type { EmailAdapter, FolderDescriptor } from "../canonical/adapter.js";
import type { CanonicalEnvelope, ContentCoverage, NormalizedFolder, ParseStatus } from "../canonical/envelope.js";
import type { Verdict } from "../engine/verdict.js";
import type { InMemoryPersonalPolicyStore } from "../engine/layers/personalRules.js";
import type { ThreatFeedCache } from "../engine/layers/globalIntelligence.js";
import {
  annotateRelationshipHistory,
  applyRelationshipObservationToSnapshot,
  createRelationshipObservation,
  type RelationshipHistoryWorkerSnapshot,
  type RelationshipObservation,
} from "../engine/relationshipHistory.js";
import type { CommunityReportContext } from "../community/types.js";
import { buildCommunityReportContext } from "../community/fingerprint.js";
import type { ScanResult } from "../engine/pipeline.js";
import { scanMessageThroughPortableCore } from "../core/portableCore.js";
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

function initialCounters(input?: Partial<ScanCounters>): ScanCounters {
  const source = input ?? {};
  const integer = (value: unknown) => Number.isFinite(value) ? Math.max(0, Math.floor(Number(value))) : 0;
  return {
    examined: integer(source.examined),
    safe: integer(source.safe),
    review: integer(source.review),
    highRisk: integer(source.highRisk),
    confirmedThreat: integer(source.confirmedThreat),
    unknown: integer(source.unknown),
    skipped: integer(source.skipped),
    malformed: integer(source.malformed),
  };
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
  /** Server-only canonical destinations for the explicit Analyze Links action. */
  links: CanonicalEnvelope["links"];
  unsubscribe: UnsubscribeCapability;
  communityReport: CommunityReportContext;
}

export type DiagnosticParseStatus = ParseStatus | "bounded sufficient";

export interface ScanDiagnosticSummary {
  subject: string;
  fromAddress: string | null;
  fromDomain: string | null;
  folder: string;
  verdict: Verdict;
  score: number;
  /** Human-facing parser/coverage state used by the local diagnostic table. */
  parseStatus: DiagnosticParseStatus;
  /** Machine-readable coverage remains separate from MIME parser integrity. */
  contentCoverage: ContentCoverage;
  parseNotes: string[];
  /** Privacy-safe reasons explaining how uncertainty affected the decision. */
  decisionNotes: string[];
  evidenceCodes: string[];
  /** Server-only until converted into opaque action tokens. */
  actionContext: ScanActionContext;
  /** Added by the API server after action-token registration. */
  reviewAction?: unknown;
  unsubscribeAction?: unknown;
}

function diagnosticSummary(result: ScanResult): ScanDiagnosticSummary {
  const contentCoverage = result.envelope.diagnostics.contentCoverage;
  const boundedSufficient = contentCoverage === "bounded_sufficient";
  const parseNotes = result.envelope.parseNotes.filter((note) =>
    !boundedSufficient || !/^Readable MIME content was bounded to \d+ decoded characters per alternative\.$/.test(note),
  );
  const decisionNotes = new Set<string>();
  const transport = result.scored.layerResults.find((layer) => layer.layer === "transport_auth");
  const safetyBlockingLayers = result.scored.layerResults.filter(
    (layer) => layer.incomplete && layer.blocksSafeVerdict && layer.incompleteReason,
  );

  if (result.scored.verdict === "unknown") {
    if (result.envelope.diagnostics.contentCoverage === "insufficient") {
      decisionNotes.add("Safe was withheld because readable message coverage was insufficient.");
    }
    for (const layer of safetyBlockingLayers) decisionNotes.add(layer.incompleteReason!);
    if (boundedSufficient && transport?.incomplete) {
      decisionNotes.add("Bounded content requires an authenticated sender identity before it can be classified Safe.");
      if (transport.incompleteReason) decisionNotes.add(transport.incompleteReason);
    }
  }
  if (
    result.scored.evidence.some((item) => item.code === "CREDENTIAL_PHISH_INTENT") &&
    transport?.incomplete
  ) {
    decisionNotes.add("Sender authentication could not be trusted, so identity-based intent suppression was not applied.");
  }
  if (result.scored.verdict === "safe" && result.scored.score > 0) {
    decisionNotes.add("Low-confidence context remained below the Review threshold; no warning decision was made.");
  }

  return {
    subject: result.envelope.subject || "(no subject)",
    fromAddress: result.envelope.from.address,
    fromDomain: result.envelope.from.domain,
    folder: result.envelope.providerFolderName,
    verdict: result.scored.verdict,
    score: result.scored.score,
    parseStatus: boundedSufficient ? "bounded sufficient" : result.envelope.parseStatus,
    contentCoverage,
    parseNotes,
    decisionNotes: [...decisionNotes],
    evidenceCodes: result.scored.evidence
      .filter((item) => item.scoreContribution !== 0)
      .map((item) => item.code),
    actionContext: {
      providerNativeId: result.envelope.providerNativeId,
      messageId: result.envelope.messageId,
      exceptionKey: messageExceptionKey(result.envelope),
      senderAddress: result.envelope.from.address,
      normalizedFolder: result.envelope.folder,
      links: structuredClone(result.envelope.links),
      unsubscribe: unsubscribeCapability(result.envelope),
      communityReport: buildCommunityReportContext(result.envelope, result.scored),
    },
  };
}

export interface ScanWorkflowCheckpoint {
  currentCursor: string | null;
  folderCursors: Record<string, string>;
  completedFolders: string[];
  seenSenderHashes: string[];
  seenMessageHashes: string[];
}

export interface ScanResumeInput {
  currentCursor?: string | null;
  folderCursors?: Record<string, string>;
  completedFolders?: string[];
  seenSenderHashes?: string[];
  seenMessageHashes?: string[];
  counters?: Partial<ScanCounters>;
}

export interface ScanProgress {
  counters: ScanCounters;
  /** Warning, threat and Unknown verdicts are surfaced here; Safe stays in the compact audit. */
  suspiciousCards: ScanResult[];
  /** Privacy-reduced local audit plus opaque user-action tokens added by the API layer. */
  diagnosticSummaries: ScanDiagnosticSummary[];
  /** Provider cursor retained only between Worker and server; never send this field to browser JavaScript. */
  cursor: string | null;
  /** Server-only resumability checkpoint. It contains no raw sender/message identity. */
  checkpoint: ScanWorkflowCheckpoint;
  /** Server-only privacy-reduced observations committed to encrypted local relationship history. */
  relationshipObservations: RelationshipObservation[];
  done: boolean;
}

export interface ScanDeps {
  personalPolicy: InMemoryPersonalPolicyStore;
  threatFeed: ThreatFeedCache;
  relationshipHistory?: RelationshipHistoryWorkerSnapshot;
}

function scanWithPortableCore(envelope: CanonicalEnvelope, deps: ScanDeps): ScanResult {
  return scanMessageThroughPortableCore(envelope, deps.personalPolicy, deps.threatFeed.getVerifiedEntries());
}

function isSuspicious(result: ScanResult): boolean {
  return result.scored.verdict === "review" ||
    result.scored.verdict === "high_risk" ||
    result.scored.verdict === "confirmed_threat" ||
    result.scored.verdict === "unknown";
}

function stableScanHash(namespace: string, value: string): string {
  return createHash("sha256")
    .update(`email-shield-scan-${namespace}-v1\0`, "utf8")
    .update(value, "utf8")
    .digest("hex");
}

/**
 * Adds only scan-local recurrence evidence. Hashes are used so the resumable
 * checkpoint can preserve recurrence without persisting sender addresses.
 */
function annotateSenderRecurrence(envelope: CanonicalEnvelope, seenSenderHashes: Set<string>): void {
  const senderAddress = envelope.from.address?.trim().toLowerCase() ?? "";
  const senderHash = senderAddress ? stableScanHash("sender", senderAddress) : "";
  envelope.threadContext.senderPreviouslySeenInScan = Boolean(senderHash && seenSenderHashes.has(senderHash));
  if (senderHash) seenSenderHashes.add(senderHash);
}

function messageIdentityHash(envelope: CanonicalEnvelope): string {
  return stableScanHash("message", `${envelope.provider}\0${envelope.messageId || envelope.providerNativeId}`);
}

function relationshipObservationFor(
  envelope: CanonicalEnvelope,
  result: ScanResult,
  deps: ScanDeps,
): RelationshipObservation | null {
  const observation = createRelationshipObservation(
    envelope,
    result.scored.verdict,
    deps.relationshipHistory,
  );
  return applyRelationshipObservationToSnapshot(deps.relationshipHistory, observation)
    ? observation
    : null;
}

function checkpoint(
  currentCursor: string | null,
  folderCursors: Record<string, string>,
  completedFolders: Set<string>,
  seenSenderHashes: Set<string>,
  seenMessageHashes: Set<string>,
): ScanWorkflowCheckpoint {
  return {
    currentCursor,
    folderCursors: { ...folderCursors },
    completedFolders: [...completedFolders],
    seenSenderHashes: [...seenSenderHashes],
    seenMessageHashes: [...seenMessageHashes],
  };
}

const DEFAULT_PAGE_SIZE = 50;

export async function* quickScan(
  adapter: EmailAdapter,
  deps: ScanDeps,
  signal: AbortSignal,
  pageSize = DEFAULT_PAGE_SIZE,
  maxMessages = pageSize,
  resume: ScanResumeInput = {},
): AsyncGenerator<ScanProgress> {
  await adapter.connect(signal);
  try {
    const folders = await adapter.listFolders(signal);
    const inbox = folders.find((folder) => folder.normalized === "inbox");
    if (!inbox) {
      throw new Error(`Inbox folder was not found. Discovered folders: ${folders.map((folder) => folder.providerFolderName).join(", ") || "none"}.`);
    }

    const counters = initialCounters(resume.counters);
    const seenSenderHashes = new Set(resume.seenSenderHashes ?? []);
    const seenMessageHashes = new Set<string>();
    const boundedPageSize = Math.max(1, Math.floor(pageSize));
    const boundedLimit = Math.max(1, Math.floor(maxMessages));
    let cursor: string | null = resume.currentCursor ?? null;
    let done = false;

    while (!done && counters.examined < boundedLimit) {
      if (signal.aborted) return;
      const remaining = boundedLimit - counters.examined;
      const requestSize = Math.min(boundedPageSize, remaining);
      const previousCursor = cursor;
      const page = await adapter.fetchPage(inbox, cursor, requestSize, signal);
      const suspiciousCards: ScanResult[] = [];
      const diagnosticSummaries: ScanDiagnosticSummary[] = [];
      const relationshipObservations: RelationshipObservation[] = [];

      for (const envelope of page.envelopes) {
        if (signal.aborted) return;
        annotateSenderRecurrence(envelope, seenSenderHashes);
        annotateRelationshipHistory(envelope, deps.relationshipHistory);
        const result = scanWithPortableCore(envelope, deps);
        tally(counters, result);
        diagnosticSummaries.push(diagnosticSummary(result));
        if (isSuspicious(result)) suspiciousCards.push(result);
        const observation = relationshipObservationFor(envelope, result, deps);
        if (observation) relationshipObservations.push(observation);
      }

      const reachedLimit = counters.examined >= boundedLimit;
      done = page.done || reachedLimit || !page.nextCursor;
      cursor = done ? null : page.nextCursor;

      yield {
        counters: { ...counters },
        suspiciousCards,
        diagnosticSummaries,
        cursor,
        checkpoint: checkpoint(cursor, {}, new Set(), seenSenderHashes, seenMessageHashes),
        relationshipObservations,
        done,
      };

      if (!done && page.envelopes.length === 0 && page.nextCursor === previousCursor) {
        throw new Error("The provider returned an empty page without advancing the mailbox cursor.");
      }
    }
  } finally {
    await adapter.disconnect();
  }
}

export async function* fullMailboxAudit(
  adapter: EmailAdapter,
  deps: ScanDeps,
  signal: AbortSignal,
  opts: {
    includeExcludedFolders?: boolean;
    pageSize?: number;
    resumeCursors?: Record<string, string | null>;
    resume?: ScanResumeInput;
  } = {},
): AsyncGenerator<ScanProgress & { folder: string }> {
  const pageSize = opts.pageSize ?? DEFAULT_PAGE_SIZE;
  const resume = opts.resume ?? {
    folderCursors: Object.fromEntries(Object.entries(opts.resumeCursors ?? {}).filter((entry): entry is [string, string] => typeof entry[1] === "string")),
  };
  await adapter.connect(signal);
  const seenMessageHashes = new Set(resume.seenMessageHashes ?? []);
  const seenSenderHashes = new Set(resume.seenSenderHashes ?? []);
  const counters = initialCounters(resume.counters);
  const completedFolders = new Set(resume.completedFolders ?? []);
  const folderCursors: Record<string, string> = { ...(resume.folderCursors ?? {}) };

  try {
    const allFolders = await adapter.listFolders(signal);
    const targetFolders: FolderDescriptor[] = opts.includeExcludedFolders
      ? allFolders
      : allFolders.filter((folder) => folder.includedByDefault);
    if (targetFolders.length === 0) {
      throw new Error(`No eligible mailbox folders were found. Discovered folders: ${allFolders.map((folder) => folder.providerFolderName).join(", ") || "none"}.`);
    }

    const targetNames = new Set(targetFolders.map((folder) => folder.providerFolderName));
    for (const completed of [...completedFolders]) {
      if (!targetNames.has(completed)) completedFolders.delete(completed);
    }

    for (const folder of targetFolders) {
      if (completedFolders.has(folder.providerFolderName)) continue;
      let cursor: string | null = folderCursors[folder.providerFolderName] ?? null;
      let done = false;

      while (!done) {
        if (signal.aborted) return;
        const previousCursor = cursor;
        const page = await adapter.fetchPage(folder, cursor, pageSize, signal);
        const suspiciousCards: ScanResult[] = [];
        const diagnosticSummaries: ScanDiagnosticSummary[] = [];
        const relationshipObservations: RelationshipObservation[] = [];

        for (const envelope of page.envelopes) {
          if (signal.aborted) return;
          const identityHash = messageIdentityHash(envelope);
          if (seenMessageHashes.has(identityHash)) continue;
          seenMessageHashes.add(identityHash);
          annotateSenderRecurrence(envelope, seenSenderHashes);
          annotateRelationshipHistory(envelope, deps.relationshipHistory);
          const result = scanWithPortableCore(envelope, deps);
          tally(counters, result);
          diagnosticSummaries.push(diagnosticSummary(result));
          if (isSuspicious(result)) suspiciousCards.push(result);
          const observation = relationshipObservationFor(envelope, result, deps);
          if (observation) relationshipObservations.push(observation);
        }

        cursor = page.nextCursor;
        done = page.done || !page.nextCursor;
        if (done) {
          completedFolders.add(folder.providerFolderName);
          delete folderCursors[folder.providerFolderName];
          cursor = null;
        } else if (cursor) {
          folderCursors[folder.providerFolderName] = cursor;
        }

        const allDone = targetFolders.every((target) => completedFolders.has(target.providerFolderName));
        yield {
          counters: { ...counters },
          suspiciousCards,
          diagnosticSummaries,
          cursor,
          checkpoint: checkpoint(null, folderCursors, completedFolders, seenSenderHashes, seenMessageHashes),
          relationshipObservations,
          done: allDone,
          folder: folder.providerFolderName,
        };

        if (!done && page.envelopes.length === 0 && page.nextCursor === previousCursor) {
          throw new Error("The provider returned an empty page without advancing the mailbox cursor.");
        }
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
  resume: ScanResumeInput = {},
): AsyncGenerator<ScanProgress> {
  await adapter.connect(signal);
  try {
    const folders = await adapter.listFolders(signal);
    const spam = folders.find((folder) => folder.normalized === "spam");
    if (!spam) {
      throw new Error(`Spam/Junk folder was not found. Discovered folders: ${folders.map((folder) => folder.providerFolderName).join(", ") || "none"}.`);
    }

    const counters = initialCounters(resume.counters);
    const seenSenderHashes = new Set(resume.seenSenderHashes ?? []);
    const seenMessageHashes = new Set<string>();
    let cursor: string | null = resume.currentCursor ?? null;
    let done = false;

    while (!done) {
      if (signal.aborted) return;
      const previousCursor = cursor;
      const page = await adapter.fetchPage(spam, cursor, pageSize, signal);
      const suspiciousCards: ScanResult[] = [];
      const diagnosticSummaries: ScanDiagnosticSummary[] = [];
      const relationshipObservations: RelationshipObservation[] = [];

      for (const envelope of page.envelopes) {
        if (signal.aborted) return;
        annotateSenderRecurrence(envelope, seenSenderHashes);
        annotateRelationshipHistory(envelope, deps.relationshipHistory);
        const result = scanWithPortableCore(envelope, deps);
        tally(counters, result);
        diagnosticSummaries.push(diagnosticSummary(result));
        if (isSuspicious(result)) suspiciousCards.push(result);
        const observation = relationshipObservationFor(envelope, result, deps);
        if (observation) relationshipObservations.push(observation);
      }

      cursor = page.nextCursor;
      done = page.done || !page.nextCursor;
      if (done) cursor = null;
      yield {
        counters: { ...counters },
        suspiciousCards,
        diagnosticSummaries,
        cursor,
        checkpoint: checkpoint(cursor, {}, new Set(), seenSenderHashes, seenMessageHashes),
        relationshipObservations,
        done,
      };

      if (!done && page.envelopes.length === 0 && page.nextCursor === previousCursor) {
        throw new Error("The provider returned an empty page without advancing the mailbox cursor.");
      }
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
