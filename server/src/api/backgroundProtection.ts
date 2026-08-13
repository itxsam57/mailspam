import { randomUUID } from "node:crypto";
import { Worker } from "node:worker_threads";
import type { CommunityNetwork } from "../community/network.js";
import type { ScanProgress, ScanCounters } from "../workflows/scanWorkflows.js";
import type { AccountPlatformService } from "../platform/accountFamilyService.js";
import { mergeVerifiedAndFamilyIntelligence } from "../platform/familyThreatFeedAdapter.js";
import { defaultRelationshipHistoryRepository } from "./defaultRelationshipHistoryRepository.js";
import { defaultScanStateRepository } from "./defaultScanStateRepository.js";
import { defaultConsumerStateRepository } from "./defaultConsumerStateRepository.js";
import {
  MAX_BACKGROUND_INTERVAL_MINUTES,
  MIN_BACKGROUND_INTERVAL_MINUTES,
  type BackgroundProtectionErrorCode,
  type BackgroundProtectionRecord,
  type BackgroundProtectionRepository,
} from "./backgroundProtectionPersistence.js";
import { defaultBackgroundProtectionRepository } from "./defaultBackgroundProtectionRepository.js";
import { scanStallReason, snapshotVerifiedFeedAndRefresh, type ScanProgressClock } from "./scanStream.js";
import { sessionStore, type AccountSession, type SessionStore } from "./sessionStore.js";
import { emptyScanCounters, type ScanHistoryRecord } from "./scanStatePersistence.js";

const SCHEDULER_TICK_MS = 15_000;
const CONFLICT_RETRY_MS = 5 * 60_000;
const BACKGROUND_SCAN_DEADLINE_MS = 4 * 60_000;
const BACKGROUND_FIRST_PROGRESS_TIMEOUT_MS = 90_000;
const BACKGROUND_NEXT_PROGRESS_TIMEOUT_MS = 60_000;
const DEFAULT_INTERVAL_MINUTES = 60;
const DEFAULT_PAGE_SIZE = 20;
const LIVE_IMAP_PAGE_SIZE = 2;
const LIVE_IMAP_MESSAGE_LIMIT = 10;

export class BackgroundProtectionRunError extends Error {
  constructor(readonly code: Exclude<BackgroundProtectionErrorCode, null>, message: string) {
    super(message);
    this.name = "BackgroundProtectionRunError";
  }
}

export interface BackgroundProtectionExecutor {
  execute(session: AccountSession): Promise<void>;
}

export interface BackgroundProtectionCoordinatorOptions {
  repository?: BackgroundProtectionRepository;
  sessions?: Pick<SessionStore, "list">;
  executor: BackgroundProtectionExecutor;
  now?: () => number;
}

export function nextBackgroundRunAt(now: number, intervalMinutes: number, consecutiveFailures = 0): number {
  const intervalMs = intervalMinutes * 60_000;
  if (consecutiveFailures <= 0) return now + intervalMs;
  const failureBackoff = Math.min(6 * 60 * 60_000, 5 * 60_000 * (2 ** Math.min(6, consecutiveFailures - 1)));
  return now + Math.min(intervalMs, failureBackoff);
}

export function publicBackgroundProtectionStatus(
  record: BackgroundProtectionRecord | null,
  persistent: boolean,
  active: boolean,
) {
  const value = record ?? {
    enabled: false,
    intervalMinutes: DEFAULT_INTERVAL_MINUTES,
    nextRunAt: null,
    lastAttemptAt: null,
    lastCompletedAt: null,
    status: "paused" as const,
    consecutiveFailures: 0,
    lastErrorCode: null,
  };
  return {
    ...value,
    persistent,
    active,
    limits: {
      minimumIntervalMinutes: MIN_BACKGROUND_INTERVAL_MINUTES,
      maximumIntervalMinutes: MAX_BACKGROUND_INTERVAL_MINUTES,
      maximumConcurrentScans: 1,
      maximumMessagesPerRun: DEFAULT_PAGE_SIZE,
      maximumRunMinutes: BACKGROUND_SCAN_DEADLINE_MS / 60_000,
    },
  };
}

export class BackgroundProtectionCoordinator {
  private readonly repository: BackgroundProtectionRepository;
  private readonly sessions: Pick<SessionStore, "list">;
  private readonly executor: BackgroundProtectionExecutor;
  private readonly now: () => number;
  private activeAccountKey: string | null = null;
  private readonly removedAccountKeys = new Set<string>();
  private timer: NodeJS.Timeout | null = null;

  constructor(options: BackgroundProtectionCoordinatorOptions) {
    this.repository = options.repository ?? defaultBackgroundProtectionRepository;
    this.sessions = options.sessions ?? sessionStore;
    this.executor = options.executor;
    this.now = options.now ?? Date.now;
  }

  start(): void {
    if (this.timer) return;
    this.repository.recoverInterrupted(this.now());
    this.timer = setInterval(() => { void this.runDue(); }, SCHEDULER_TICK_MS);
    this.timer.unref();
    void this.runDue();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  configure(accountKey: string, enabled: boolean, intervalMinutes: number, now = this.now()): BackgroundProtectionRecord {
    if (!Number.isSafeInteger(intervalMinutes) || intervalMinutes < MIN_BACKGROUND_INTERVAL_MINUTES || intervalMinutes > MAX_BACKGROUND_INTERVAL_MINUTES) {
      throw new Error(`Background protection interval must be ${MIN_BACKGROUND_INTERVAL_MINUTES}-${MAX_BACKGROUND_INTERVAL_MINUTES} minutes.`);
    }
    const previous = this.repository.get(accountKey);
    const record: BackgroundProtectionRecord = enabled
      ? {
          enabled: true,
          intervalMinutes,
          nextRunAt: previous?.enabled
            ? Math.min(previous.nextRunAt ?? now, nextBackgroundRunAt(now, intervalMinutes))
            : now + 60_000,
          lastAttemptAt: previous?.lastAttemptAt ?? null,
          lastCompletedAt: previous?.lastCompletedAt ?? null,
          status: "scheduled",
          consecutiveFailures: previous?.consecutiveFailures ?? 0,
          lastErrorCode: null,
        }
      : {
          enabled: false,
          intervalMinutes,
          nextRunAt: null,
          lastAttemptAt: previous?.lastAttemptAt ?? null,
          lastCompletedAt: previous?.lastCompletedAt ?? null,
          status: "paused",
          consecutiveFailures: previous?.consecutiveFailures ?? 0,
          lastErrorCode: previous?.lastErrorCode ?? null,
        };
    this.repository.save(accountKey, record);
    return record;
  }

  status(accountKey: string): ReturnType<typeof publicBackgroundProtectionStatus> {
    return publicBackgroundProtectionStatus(
      this.repository.get(accountKey),
      this.repository.persistent,
      this.activeAccountKey === accountKey,
    );
  }

  remove(accountKey: string): void {
    this.removedAccountKeys.add(accountKey);
    this.repository.remove(accountKey);
  }

  async runDue(now = this.now()): Promise<boolean> {
    if (this.activeAccountKey) return false;
    const due = this.repository.list()
      .filter(({ record }) => record.enabled && record.nextRunAt !== null && record.nextRunAt <= now)
      .sort((left, right) => (left.record.nextRunAt ?? 0) - (right.record.nextRunAt ?? 0))[0];
    if (!due) return false;

    const session = this.sessions.list().find((candidate) => candidate.policyAccountKey === due.accountKey);
    if (!session || session.closing || session.activeScanWorker) {
      this.repository.save(due.accountKey, {
        ...due.record,
        status: "deferred",
        nextRunAt: now + CONFLICT_RETRY_MS,
        lastErrorCode: session?.activeScanWorker ? "scan_conflict" : "provider_unavailable",
      });
      return false;
    }

    this.activeAccountKey = due.accountKey;
    this.removedAccountKeys.delete(due.accountKey);
    this.repository.save(due.accountKey, {
      ...due.record,
      status: "running",
      nextRunAt: due.record.nextRunAt,
      lastAttemptAt: now,
      lastErrorCode: null,
    });

    try {
      await this.executor.execute(session);
      const completedAt = this.now();
      if (!this.removedAccountKeys.has(due.accountKey)) this.repository.save(due.accountKey, {
        ...due.record,
        status: "completed",
        nextRunAt: nextBackgroundRunAt(completedAt, due.record.intervalMinutes),
        lastAttemptAt: now,
        lastCompletedAt: completedAt,
        consecutiveFailures: 0,
        lastErrorCode: null,
      });
    } catch (error) {
      const failedAt = this.now();
      const consecutiveFailures = Math.min(16, due.record.consecutiveFailures + 1);
      const code = error instanceof BackgroundProtectionRunError ? error.code : "provider_unavailable";
      if (!this.removedAccountKeys.has(due.accountKey)) this.repository.save(due.accountKey, {
        ...due.record,
        status: "failed",
        nextRunAt: nextBackgroundRunAt(failedAt, due.record.intervalMinutes, consecutiveFailures),
        lastAttemptAt: now,
        consecutiveFailures,
        lastErrorCode: code,
      });
    } finally {
      this.removedAccountKeys.delete(due.accountKey);
      this.activeAccountKey = null;
    }
    return true;
  }
}

export class WorkerBackgroundProtectionExecutor implements BackgroundProtectionExecutor {
  constructor(
    private readonly community: CommunityNetwork,
    private readonly accountPlatform?: Pick<AccountPlatformService, "familyThreatSnapshot">,
  ) {}

  async execute(session: AccountSession): Promise<void> {
    await this.executeWithSummary(session);
  }

  /**
   * One authoritative bounded Worker protection path shared by scheduled and
   * near-real-time triggers. Realtime may consume the counters, but it does not
   * get a separate scanner, policy model or threat-feed path.
   */
  async executeWithSummary(session: AccountSession): Promise<ScanCounters> {
    if (session.activeScanWorker) throw new BackgroundProtectionRunError("scan_conflict", "An account scan is already active.");
    const now = Date.now();
    const record: ScanHistoryRecord = {
      scanId: randomUUID(),
      type: "quick",
      status: "running",
      startedAt: now,
      updatedAt: now,
      completedAt: null,
      counters: emptyScanCounters(),
      checkpoint: {
        currentCursor: null,
        folderCursors: {},
        completedFolders: [],
        seenSenderHashes: [],
        seenMessageHashes: [],
      },
    };

    let relationshipHistory;
    try {
      relationshipHistory = defaultRelationshipHistoryRepository.workerSnapshot(session.policyAccountKey);
      defaultScanStateRepository.save(session.policyAccountKey, record);
    } catch (error) {
      throw new BackgroundProtectionRunError("protected_state_failure", `Protected background scan state could not initialize: ${error instanceof Error ? error.message : String(error)}`);
    }

    const liveImap = session.config.mode === "live" && ["icloud", "yahoo", "imap"].includes(session.provider);
    const pageSize = liveImap ? LIVE_IMAP_PAGE_SIZE : DEFAULT_PAGE_SIZE;
    const maxMessages = liveImap ? LIVE_IMAP_MESSAGE_LIMIT : DEFAULT_PAGE_SIZE;
    const globalThreatFeedEntries = snapshotVerifiedFeedAndRefresh(this.community);
    const threatFeedEntries = this.accountPlatform
      ? mergeVerifiedAndFamilyIntelligence(
          globalThreatFeedEntries,
          this.accountPlatform.familyThreatSnapshot(session.policyAccountKey),
        )
      : globalThreatFeedEntries;
    const workerUrl = new URL("../workers/scanWorker.js", import.meta.url);
    let worker: Worker;
    try {
      worker = new Worker(workerUrl, {
        workerData: {
          config: session.config,
          type: "quick",
          pageSize,
          maxMessages,
          personalPolicy: session.personalPolicy.snapshot(),
          threatFeedEntries,
          relationshipHistory,
        },
      });
    } catch (error) {
      record.status = "failed";
      record.updatedAt = Date.now();
      defaultScanStateRepository.save(session.policyAccountKey, record);
      throw new BackgroundProtectionRunError("provider_unavailable", `Background scan worker could not start: ${error instanceof Error ? error.message : String(error)}`);
    }

    session.activeScanWorker = worker;
    await new Promise<void>((resolve, reject) => {
      let settled = false;
      let completionRecorded = false;
      const clock: ScanProgressClock = { startedAt: Date.now(), lastProgressAt: Date.now(), progressSeen: false };

      const saveFailure = (code: Exclude<BackgroundProtectionErrorCode, null>, message: string) => {
        if (settled) return;
        settled = true;
        clearInterval(stallTimer);
        clearTimeout(deadline);
        record.status = "failed";
        record.completedAt = null;
        record.updatedAt = Date.now();
        try { defaultScanStateRepository.save(session.policyAccountKey, record); }
        catch { code = "protected_state_failure"; }
        try { worker.postMessage({ type: "cancel" }); } catch {}
        void worker.terminate();
        reject(new BackgroundProtectionRunError(code, message));
      };

      const complete = () => {
        if (settled || completionRecorded) return;
        record.status = "completed";
        record.completedAt = Date.now();
        record.updatedAt = record.completedAt;
        record.checkpoint = null;
        try { defaultScanStateRepository.save(session.policyAccountKey, record); }
        catch {
          saveFailure("protected_state_failure", "Background scan completed but protected history could not finalize.");
          return;
        }
        completionRecorded = true;
      };

      const stallTimer = setInterval(() => {
        const reason = scanStallReason(
          clock,
          Date.now(),
          BACKGROUND_FIRST_PROGRESS_TIMEOUT_MS,
          BACKGROUND_NEXT_PROGRESS_TIMEOUT_MS,
        );
        if (reason) saveFailure("resource_deadline", reason);
      }, 5_000);
      stallTimer.unref();
      const deadline = setTimeout(() => {
        saveFailure("resource_deadline", "Background scan exceeded its resource deadline.");
      }, BACKGROUND_SCAN_DEADLINE_MS);
      deadline.unref();

      worker.on("message", (message) => {
        if (settled) return;
        if (message.type === "progress") {
          clock.progressSeen = true;
          clock.lastProgressAt = Date.now();
          const progress = message.progress as ScanProgress;
          try {
            defaultRelationshipHistoryRepository.merge(session.policyAccountKey, progress.relationshipObservations ?? []);
            record.counters = { ...progress.counters };
            record.checkpoint = {
              currentCursor: progress.checkpoint.currentCursor,
              folderCursors: { ...progress.checkpoint.folderCursors },
              completedFolders: [...progress.checkpoint.completedFolders],
              seenSenderHashes: [...progress.checkpoint.seenSenderHashes],
              seenMessageHashes: [...progress.checkpoint.seenMessageHashes],
            };
            record.updatedAt = Date.now();
            defaultScanStateRepository.save(session.policyAccountKey, record);
          } catch {
            saveFailure("protected_state_failure", "Background scan stopped because protected progress could not be saved.");
          }
        } else if (message.type === "complete") complete();
        else if (message.type === "error") saveFailure("provider_unavailable", "Background provider scan failed.");
      });
      worker.once("error", () => saveFailure("provider_unavailable", "Background scan worker failed."));
      worker.once("exit", (code) => {
        if (settled) return;
        if (completionRecorded && code === 0) {
          settled = true;
          clearInterval(stallTimer);
          clearTimeout(deadline);
          resolve();
          return;
        }
        saveFailure("provider_unavailable", code === 0
          ? "Background scan worker exited before completion."
          : "Background scan worker exited unexpectedly.");
      });
    }).finally(() => {
      if (session.activeScanWorker === worker) session.activeScanWorker = null;
    });

    try {
      const counters = record.counters;
      const severity = counters.confirmedThreat > 0
        ? "critical"
        : counters.highRisk > 0
          ? "warning"
          : counters.review + counters.unknown > 0
            ? "attention"
            : "info";
      const kind = counters.confirmedThreat > 0 ? "protected" : counters.highRisk + counters.review + counters.unknown > 0 ? "flagged" : "protected";
      defaultConsumerStateRepository.appendActivity(session.policyAccountKey, {
        kind,
        severity,
        provider: session.config.provider,
        title: counters.confirmedThreat > 0 ? "Automatic protection handled confirmed threats" : "Automatic mailbox protection completed",
        detail: `A bounded automatic protection pass examined ${counters.examined} message(s): ${counters.confirmedThreat} confirmed threat(s), ${counters.highRisk} high-risk, ${counters.review} review, and ${counters.unknown} unknown. Activity stores aggregate counts only.`,
        reasonCodes: ["AUTOMATIC_PROTECTION_PASS"],
        undo: null,
      });
    } catch {
      // Scan/protection state is already committed. A secondary Activity write
      // cannot be allowed to turn a successful provider protection pass into a
      // failed one or cause duplicate provider work on retry.
    }

    return { ...record.counters };
  }
}

export function createBackgroundProtectionCoordinator(
  community: CommunityNetwork,
  accountPlatform?: Pick<AccountPlatformService, "familyThreatSnapshot">,
): BackgroundProtectionCoordinator {
  return new BackgroundProtectionCoordinator({
    repository: defaultBackgroundProtectionRepository,
    sessions: sessionStore,
    executor: new WorkerBackgroundProtectionExecutor(community, accountPlatform),
  });
}
