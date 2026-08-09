import { randomUUID } from "node:crypto";
import type { Request, RequestHandler, Response } from "express";
import { Worker } from "node:worker_threads";
import { sessionStore } from "./sessionStore.js";
import { defaultScanStateRepository } from "./defaultScanStateRepository.js";
import {
  emptyScanCounters,
  type ScanHistoryRecord,
  type ScanResumeCheckpoint,
  type ScanType,
} from "./scanStatePersistence.js";
import {
  normalizeManualUnsubscribeTarget,
  normalizeOneClickTarget,
} from "../workflows/unsubscribe.js";
import type { ScanActionContext, ScanProgress, ScanResumeInput } from "../workflows/scanWorkflows.js";
import type { CommunityNetwork } from "../community/network.js";
import type { SignedFeedEntry } from "../engine/layers/globalIntelligence.js";

const HEARTBEAT_INTERVAL_MS = 15_000;
const LIVE_IMAP_FIRST_PROGRESS_TIMEOUT_MS = 180_000;
const LIVE_IMAP_NEXT_PROGRESS_TIMEOUT_MS = 120_000;
const DEFAULT_FIRST_PROGRESS_TIMEOUT_MS = 60_000;
const DEFAULT_NEXT_PROGRESS_TIMEOUT_MS = 60_000;
const LIVE_IMAP_PAGE_SIZE = 2;
const LIVE_IMAP_QUICK_LIMIT = 10;
const DEFAULT_PAGE_SIZE = 20;

interface ActiveScanMetadata {
  scanId: string;
  stopRequested: boolean;
}

const activeScans = new Map<string, ActiveScanMetadata>();

export interface ScanProgressClock {
  startedAt: number;
  lastProgressAt: number;
  progressSeen: boolean;
}

export function scanStallReason(
  clock: ScanProgressClock,
  now: number,
  firstProgressTimeoutMs: number,
  nextProgressTimeoutMs: number,
): string | null {
  if (!clock.progressSeen && now - clock.startedAt >= firstProgressTimeoutMs) {
    return "The provider did not return the first bounded message batch before the scan deadline.";
  }
  if (clock.progressSeen && now - clock.lastProgressAt >= nextProgressTimeoutMs) {
    return "The provider stopped returning message batches before the scan deadline.";
  }
  return null;
}

/**
 * A mailbox scan must never wait for remote community-network retries.
 * The worker receives the last verified snapshot immediately while a refresh,
 * when configured, proceeds independently for the next scan.
 */
export function snapshotVerifiedFeedAndRefresh(
  community: Pick<CommunityNetwork, "remoteUrl" | "getVerifiedEntries" | "refreshFeed">,
): SignedFeedEntry[] | null {
  const snapshot = community.getVerifiedEntries();
  if (community.remoteUrl) {
    void Promise.resolve()
      .then(() => community.refreshFeed())
      .catch(() => undefined);
  }
  return snapshot;
}

/** Mark the currently active account scan as explicitly stopped by the user. */
export function requestActiveScanStop(sessionId: string): boolean {
  const active = activeScans.get(sessionId);
  if (!active) return false;
  active.stopRequested = true;
  return true;
}

export function publicScanProgress(progress: ScanProgress): Omit<ScanProgress, "cursor" | "checkpoint"> {
  const { cursor: _cursor, checkpoint: _checkpoint, ...publicProgress } = progress;
  return publicProgress;
}

function sseHeaders(res: Response): void {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-store, must-revalidate",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.socket?.setTimeout(0);
}

function registerPublicActions(
  session: NonNullable<ReturnType<typeof sessionStore.get>>,
  context: ScanActionContext,
) {
  const reviewAction = sessionStore.registerReviewAction(session, context);
  let unsubscribeAction: Record<string, unknown> = { available: false, method: "none" };
  const capability = context.unsubscribe;

  if (capability.available && capability.method !== "none" && capability.target) {
    try {
      const target = capability.method === "one_click_post"
        ? normalizeOneClickTarget(capability.target)
        : normalizeManualUnsubscribeTarget(capability.method, capability.target);
      unsubscribeAction = {
        available: true,
        method: capability.method,
        source: capability.source,
        ...sessionStore.registerUnsubscribeAction(
          session,
          capability.method,
          target,
          context.providerNativeId,
        ),
      };
    } catch {
      unsubscribeAction = { available: false, method: "none" };
    }
  }

  return { reviewAction, unsubscribeAction };
}

function isResumableStatus(status: ScanHistoryRecord["status"]): boolean {
  return status === "interrupted" || status === "failed" || status === "stopped";
}

function recordToResume(record: ScanHistoryRecord): ScanResumeInput {
  const checkpoint = record.checkpoint;
  if (!checkpoint) return { counters: record.counters };
  return {
    currentCursor: checkpoint.currentCursor,
    folderCursors: { ...checkpoint.folderCursors },
    completedFolders: [...checkpoint.completedFolders],
    seenSenderHashes: [...checkpoint.seenSenderHashes],
    seenMessageHashes: [...checkpoint.seenMessageHashes],
    counters: { ...record.counters },
  };
}

function createInitialCheckpoint(): ScanResumeCheckpoint {
  return {
    currentCursor: null,
    folderCursors: {},
    completedFolders: [],
    seenSenderHashes: [],
    seenMessageHashes: [],
  };
}

function createNewRecord(type: ScanType): ScanHistoryRecord {
  const now = Date.now();
  return {
    scanId: randomUUID(),
    type,
    status: "running",
    startedAt: now,
    updatedAt: now,
    completedAt: null,
    counters: emptyScanCounters(),
    checkpoint: createInitialCheckpoint(),
  };
}

function createHandler(options: { community: CommunityNetwork; resume: boolean }): RequestHandler {
  const { community, resume } = options;

  return (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) {
      res.status(404).json({ error: "Unknown account" });
      return;
    }
    if (session.activeScanWorker) {
      res.status(409).json({ error: "A scan is already active" });
      return;
    }

    let record: ScanHistoryRecord;
    let resumeInput: ScanResumeInput | undefined;
    let type: ScanType;

    if (resume) {
      const scanId = req.params.scanId ?? "";
      const existing = defaultScanStateRepository.get(session.policyAccountKey, scanId);
      if (!existing) {
        res.status(404).json({ error: "The requested scan history record does not exist for this account." });
        return;
      }
      if (!isResumableStatus(existing.status) || !existing.checkpoint) {
        res.status(409).json({ error: "This scan no longer has a resumable protected checkpoint." });
        return;
      }
      type = existing.type;
      resumeInput = recordToResume(existing);
      record = {
        ...existing,
        status: "running",
        updatedAt: Date.now(),
        completedAt: null,
      };
    } else {
      type = req.params.type as ScanType;
      if (!["quick", "full", "spam"].includes(type)) {
        res.status(400).json({ error: "Unknown scan type" });
        return;
      }
      record = createNewRecord(type);
    }

    try {
      defaultScanStateRepository.save(session.policyAccountKey, record);
    } catch (error) {
      res.status(500).json({
        error: `Protected scan checkpoint could not be initialized: ${error instanceof Error ? error.message : String(error)}`,
      });
      return;
    }

    sessionStore.clearScanActions(session);
    sseHeaders(res);
    res.flushHeaders();

    const writeEvent = (event: string, data: unknown) => {
      if (!res.writableEnded && !res.destroyed) {
        res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
      }
    };

    writeEvent("scan-started", {
      type,
      provider: session.provider,
      scanId: record.scanId,
      resumed: resume,
      historyPersistent: defaultScanStateRepository.persistent,
    });

    const threatFeedEntries = snapshotVerifiedFeedAndRefresh(community);
    writeEvent("scan-status", {
      phase: "community_feed",
      message: resume
        ? "Restored the protected scan checkpoint. Starting from the last confirmed provider page."
        : community.remoteUrl
          ? "Refreshing verified community protection feed separately while the mailbox scan starts with the current verified snapshot."
          : "Refreshing verified community protection feed from the current local verified snapshot while the mailbox scan starts.",
    });

    const workerUrl = new URL("../workers/scanWorker.js", import.meta.url);
    const liveImap = session.config.mode === "live" && ["icloud", "yahoo", "imap"].includes(session.provider);
    const pageSize = liveImap ? LIVE_IMAP_PAGE_SIZE : DEFAULT_PAGE_SIZE;
    const maxMessages = type === "quick"
      ? (liveImap ? LIVE_IMAP_QUICK_LIMIT : DEFAULT_PAGE_SIZE)
      : undefined;

    let worker: Worker;
    try {
      worker = new Worker(workerUrl, {
        workerData: {
          config: session.config,
          type,
          pageSize,
          maxMessages,
          resume: resumeInput,
          personalPolicy: session.personalPolicy.snapshot(),
          threatFeedEntries,
        },
      });
    } catch (error) {
      record.status = "failed";
      record.updatedAt = Date.now();
      try { defaultScanStateRepository.save(session.policyAccountKey, record); } catch {}
      writeEvent("scan-error", {
        message: `Could not start scan worker: ${error instanceof Error ? error.message : String(error)}`,
      });
      res.end();
      return;
    }

    session.activeScanWorker = worker;
    activeScans.set(session.id, { scanId: record.scanId, stopRequested: false });
    let finished = false;
    let terminalEventSent = false;
    const clock: ScanProgressClock = {
      startedAt: Date.now(),
      lastProgressAt: Date.now(),
      progressSeen: false,
    };
    const firstProgressTimeoutMs = liveImap
      ? LIVE_IMAP_FIRST_PROGRESS_TIMEOUT_MS
      : DEFAULT_FIRST_PROGRESS_TIMEOUT_MS;
    const nextProgressTimeoutMs = liveImap
      ? LIVE_IMAP_NEXT_PROGRESS_TIMEOUT_MS
      : DEFAULT_NEXT_PROGRESS_TIMEOUT_MS;

    const saveRecord = (): boolean => {
      record.updatedAt = Date.now();
      try {
        defaultScanStateRepository.save(session.policyAccountKey, record);
        return true;
      } catch {
        return false;
      }
    };

    const cleanup = () => {
      if (finished) return;
      finished = true;
      clearInterval(heartbeat);
      if (session.activeScanWorker === worker) session.activeScanWorker = null;
      const active = activeScans.get(session.id);
      if (active?.scanId === record.scanId) activeScans.delete(session.id);
      if (!res.writableEnded && !res.destroyed) res.end();
    };

    const terminateWithError = (message: string) => {
      if (finished) return;
      terminalEventSent = true;
      const active = activeScans.get(session.id);
      record.status = active?.stopRequested ? "stopped" : "failed";
      record.completedAt = null;
      saveRecord();
      writeEvent("scan-error", { message, resumable: Boolean(record.checkpoint), scanId: record.scanId });
      try { worker.postMessage({ type: "cancel" }); } catch {}
      const hardStop = setTimeout(() => { void worker.terminate(); }, 1000);
      hardStop.unref();
      cleanup();
    };

    const heartbeat = setInterval(() => {
      if (finished) return;
      const now = Date.now();
      const stalled = scanStallReason(
        clock,
        now,
        firstProgressTimeoutMs,
        nextProgressTimeoutMs,
      );
      if (stalled) {
        terminateWithError(`${stalled} The last confirmed page was saved so the scan can be resumed instead of remaining stuck.`);
        return;
      }

      const elapsedSeconds = Math.max(1, Math.floor((now - clock.lastProgressAt) / 1000));
      writeEvent("scan-status", {
        phase: clock.progressSeen ? "waiting_for_next_batch" : "waiting_for_first_batch",
        message: clock.progressSeen
          ? `The provider is preparing the next bounded batch (${elapsedSeconds}s). The last completed page is protected for resume.`
          : `The provider is preparing the first bounded batch (${elapsedSeconds}s). Stop remains available.`,
      });
    }, HEARTBEAT_INTERVAL_MS);
    heartbeat.unref();

    worker.on("message", (message) => {
      if (finished) return;
      if (message.type === "status") {
        writeEvent("scan-status", message.status);
      } else if (message.type === "progress") {
        clock.progressSeen = true;
        clock.lastProgressAt = Date.now();
        const progress = message.progress as ScanProgress;

        record.counters = { ...progress.counters };
        record.checkpoint = {
          currentCursor: progress.checkpoint.currentCursor,
          folderCursors: { ...progress.checkpoint.folderCursors },
          completedFolders: [...progress.checkpoint.completedFolders],
          seenSenderHashes: [...progress.checkpoint.seenSenderHashes],
          seenMessageHashes: [...progress.checkpoint.seenMessageHashes],
        };
        if (!saveRecord()) {
          terminateWithError("The protected scan checkpoint could not be saved. The scan was stopped rather than continuing without resumability.");
          return;
        }

        const actionsByNativeId = new Map<string, ReturnType<typeof registerPublicActions>>();
        for (const summary of progress.diagnosticSummaries ?? []) {
          const context = summary.actionContext as ScanActionContext | undefined;
          if (!context) continue;
          const actions = registerPublicActions(session, context);
          actionsByNativeId.set(context.providerNativeId, actions);
          summary.reviewAction = actions.reviewAction;
          summary.unsubscribeAction = actions.unsubscribeAction;
          delete (summary as Partial<typeof summary>).actionContext;
        }

        for (const result of progress.suspiciousCards ?? []) {
          const actions = actionsByNativeId.get(result.envelope.providerNativeId);
          if (actions) {
            (result as any).reviewAction = actions.reviewAction;
            (result as any).unsubscribeAction = actions.unsubscribeAction;
          }
          result.envelope.listHeaders = {
            listId: result.envelope.listHeaders?.listId ?? null,
            listUnsubscribe: null,
            listUnsubscribePost: null,
          };
        }

        if (!res.writableEnded && !res.destroyed) {
          res.write(`data: ${JSON.stringify(publicScanProgress(progress))}\n\n`);
        }
      } else if (message.type === "complete") {
        terminalEventSent = true;
        record.status = "completed";
        record.completedAt = Date.now();
        record.updatedAt = record.completedAt;
        record.checkpoint = null;
        if (!saveRecord()) {
          writeEvent("scan-error", {
            message: "The mailbox scan completed, but its protected history record could not be finalized.",
            scanId: record.scanId,
          });
        } else {
          writeEvent("scan-complete", { scanId: record.scanId, historySaved: true });
        }
        cleanup();
      } else if (message.type === "error") {
        const active = activeScans.get(session.id);
        const stopped = active?.stopRequested === true || message.name === "AbortError";
        terminateWithError(stopped ? "Scan stopped. The last completed page is available to resume." : message.message);
      }
    });

    worker.on("error", (error) => {
      if (finished) return;
      terminateWithError(error.message);
    });

    worker.on("exit", (code) => {
      if (finished) return;
      if (!terminalEventSent) {
        const active = activeScans.get(session.id);
        const stopped = active?.stopRequested === true;
        terminateWithError(stopped
          ? "Scan stopped. The last completed page is available to resume."
          : code === 0
            ? "Scan worker exited before returning a terminal result. The last completed page is available to resume."
            : `Scan worker exited unexpectedly with code ${code}. The last completed page is available to resume.`);
      }
    });

    // A page refresh or temporary EventSource disconnect must not destroy the
    // Worker. It continues advancing encrypted checkpoints in this process.
    // Explicit Stop remains the only browser action that cancels the Worker.
    res.on("close", () => {
      // Intentionally no cancellation here.
    });
  };
}

export function createScanStreamHandler(options: { community: CommunityNetwork }): RequestHandler {
  return createHandler({ ...options, resume: false });
}

export function createResumeScanStreamHandler(options: { community: CommunityNetwork }): RequestHandler {
  return createHandler({ ...options, resume: true });
}
