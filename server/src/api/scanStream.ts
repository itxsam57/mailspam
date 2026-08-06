import type { Request, RequestHandler, Response } from "express";
import { Worker } from "node:worker_threads";
import { sessionStore } from "./sessionStore.js";
import {
  normalizeManualUnsubscribeTarget,
  normalizeOneClickTarget,
} from "../workflows/unsubscribe.js";
import type { ScanActionContext } from "../workflows/scanWorkflows.js";
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

export function createScanStreamHandler(options: { community: CommunityNetwork }): RequestHandler {
  const { community } = options;

  return (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) {
      res.status(404).json({ error: "Unknown account" });
      return;
    }

    const type = req.params.type as "quick" | "full" | "spam";
    if (!["quick", "full", "spam"].includes(type)) {
      res.status(400).json({ error: "Unknown scan type" });
      return;
    }
    if (session.activeScanWorker) {
      res.status(409).json({ error: "A scan is already active" });
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

    writeEvent("scan-started", { type, provider: session.provider });

    const threatFeedEntries = snapshotVerifiedFeedAndRefresh(community);
    writeEvent("scan-status", {
      phase: "community_feed",
      message: community.remoteUrl
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
          personalPolicy: session.personalPolicy.snapshot(),
          threatFeedEntries,
        },
      });
    } catch (error) {
      writeEvent("scan-error", {
        message: `Could not start scan worker: ${error instanceof Error ? error.message : String(error)}`,
      });
      res.end();
      return;
    }

    session.activeScanWorker = worker;
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

    const cleanup = () => {
      if (finished) return;
      finished = true;
      clearInterval(heartbeat);
      if (session.activeScanWorker === worker) session.activeScanWorker = null;
      if (!res.writableEnded) res.end();
    };

    const terminateWithError = (message: string) => {
      if (finished) return;
      terminalEventSent = true;
      writeEvent("scan-error", { message });
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
        terminateWithError(`${stalled} The scan was stopped instead of remaining stuck. Retry once; if it repeats, reconnect the account.`);
        return;
      }

      const elapsedSeconds = Math.max(1, Math.floor((now - clock.lastProgressAt) / 1000));
      writeEvent("scan-status", {
        phase: clock.progressSeen ? "waiting_for_next_batch" : "waiting_for_first_batch",
        message: clock.progressSeen
          ? `The provider is preparing the next bounded batch (${elapsedSeconds}s). Stop remains available.`
          : `The provider is preparing the first bounded batch (${elapsedSeconds}s). Stop remains available.`,
      });
    }, HEARTBEAT_INTERVAL_MS);
    heartbeat.unref();

    worker.on("message", (message) => {
      if (message.type === "status") {
        writeEvent("scan-status", message.status);
      } else if (message.type === "progress") {
        clock.progressSeen = true;
        clock.lastProgressAt = Date.now();
        const progress = message.progress as { suspiciousCards?: any[]; diagnosticSummaries?: any[] };
        const actionsByNativeId = new Map<string, ReturnType<typeof registerPublicActions>>();

        for (const summary of progress.diagnosticSummaries ?? []) {
          const context = summary.actionContext as ScanActionContext | undefined;
          if (!context) continue;
          const actions = registerPublicActions(session, context);
          actionsByNativeId.set(context.providerNativeId, actions);
          summary.reviewAction = actions.reviewAction;
          summary.unsubscribeAction = actions.unsubscribeAction;
          delete summary.actionContext;
        }

        for (const result of progress.suspiciousCards ?? []) {
          const actions = actionsByNativeId.get(result.envelope.providerNativeId);
          if (actions) {
            result.reviewAction = actions.reviewAction;
            result.unsubscribeAction = actions.unsubscribeAction;
          }
          result.envelope.listHeaders = {
            listId: result.envelope.listHeaders?.listId ?? null,
            listUnsubscribe: null,
            listUnsubscribePost: null,
          };
        }

        if (!res.writableEnded && !res.destroyed) {
          res.write(`data: ${JSON.stringify(progress)}\n\n`);
        }
      } else if (message.type === "complete") {
        terminalEventSent = true;
        writeEvent("scan-complete", {});
        cleanup();
      } else if (message.type === "error") {
        terminalEventSent = true;
        writeEvent("scan-error", { message: message.message, name: message.name });
        cleanup();
      }
    });

    worker.on("error", (error) => {
      terminalEventSent = true;
      writeEvent("scan-error", { message: error.message, name: error.name });
      cleanup();
    });

    worker.on("exit", (code) => {
      if (!terminalEventSent && !finished) {
        writeEvent("scan-error", {
          message: code === 0
            ? "Scan worker exited before returning a result."
            : `Scan worker exited unexpectedly with code ${code}.`,
        });
      }
      cleanup();
    });

    res.on("close", () => {
      if (finished) return;
      try { worker.postMessage({ type: "cancel" }); } catch {}
      const hardStop = setTimeout(() => { void worker.terminate(); }, 1000);
      hardStop.unref();
      cleanup();
    });
  };
}
