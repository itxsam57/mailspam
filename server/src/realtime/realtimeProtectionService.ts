import type { AccountSession, SessionStore } from "../api/sessionStore.js";
import type { Provider } from "../canonical/envelope.js";
import { sha256Hex } from "../core/sha256.js";
import {
  InboundProtectionCoordinator,
  normalizeInboundEvent,
  type CanonicalInboundEventV1,
  type InboundEventOutcome,
  type InboundEventStateRepository,
} from "./inboundEvents.js";
import type { MailboxCheckpointProbe } from "./mailboxCheckpointProbe.js";
import type { ProviderInboundBatch } from "./providerSources.js";
import type { RealtimeProtectionProcessor } from "./realtimeProtectionProcessor.js";

export const DEFAULT_REALTIME_POLL_INTERVAL_MS = 2 * 60_000;
export const MIN_REALTIME_POLL_INTERVAL_MS = 30_000;
export const MAX_REALTIME_POLL_INTERVAL_MS = 15 * 60_000;

export interface RealtimeProtectionStatus {
  running: boolean;
  persistentReplayState: boolean;
  pollIntervalMs: number;
  queued: number;
  processing: number;
  connectedAccounts: number;
  lastPollAt: number | null;
  lastSuccessAt: number | null;
  lastErrorAt: number | null;
  lastErrorCode: "scan_conflict" | "provider_unavailable" | "provider_mismatch" | "processing_failure" | null;
}

export interface AccountAutomaticProtectionStatus {
  automaticProcessingEnabled: boolean;
  providerEvents: "not_configured_in_desktop_runtime";
  metadataCheckpointFallback: "available" | "unavailable";
  pollIntervalMs: number;
  persistentReplayState: boolean;
  lastPollAt: number | null;
  lastSuccessAt: number | null;
  lastErrorAt: number | null;
  lastErrorCode: RealtimeProtectionStatus["lastErrorCode"];
}

export type RealtimeProtectionOutcome = InboundEventOutcome | { status: "disabled" };

export interface MailboxReachabilitySnapshot {
  state: "checking" | "reachable" | "unavailable";
  checkedAt: number | null;
  lastReachableAt: number | null;
}

interface MailboxReachabilityRecord extends MailboxReachabilitySnapshot {
  sessionId: string;
}

function providerOf(value: string): Provider | null {
  return value === "gmail" || value === "outlook" || value === "icloud" || value === "yahoo" || value === "imap"
    ? value
    : null;
}

function boundedInterval(value: number): number {
  if (!Number.isSafeInteger(value) || value < MIN_REALTIME_POLL_INTERVAL_MS || value > MAX_REALTIME_POLL_INTERVAL_MS) {
    throw new Error(`Realtime polling interval must be ${MIN_REALTIME_POLL_INTERVAL_MS}-${MAX_REALTIME_POLL_INTERVAL_MS} ms.`);
  }
  return value;
}

function pollingEvent(
  accountKey: string,
  provider: Provider,
  previousCheckpoint: string,
  checkpoint: string,
): CanonicalInboundEventV1 {
  return {
    schemaVersion: 1,
    accountKey,
    provider,
    source: "poll",
    kind: "mailbox_changed",
    eventId: sha256Hex([
      "email-shield-poll-checkpoint-transition-v1",
      accountKey,
      provider,
      previousCheckpoint,
      checkpoint,
    ].join("\0")),
    checkpoint,
    providerMessageId: null,
  };
}

/**
 * Local near-realtime event coordinator.
 *
 * Provider push/IDLE adapters may enqueue normalized metadata-only events
 * immediately. The polling fallback first compares a provider-native opaque
 * metadata checkpoint. It establishes a protected baseline without scanning,
 * ignores unchanged mailboxes, and enters the shared replay-safe Quick scan
 * path only after the checkpoint genuinely changes AND the account's persisted
 * Continuous Protection state authorizes automatic processing.
 */
export class RealtimeProtectionService {
  readonly #sessions: Pick<SessionStore, "list">;
  readonly #coordinator: InboundProtectionCoordinator;
  readonly #pollIntervalMs: number;
  readonly #pollProbe: MailboxCheckpointProbe | null;
  readonly #protectionEnabled: (accountKey: string) => boolean;
  #timer: NodeJS.Timeout | null = null;
  #pollRunning = false;
  #lastPollAt: number | null = null;
  #lastSuccessAt: number | null = null;
  #lastErrorAt: number | null = null;
  #lastErrorCode: RealtimeProtectionStatus["lastErrorCode"] = null;
  readonly #mailboxReachabilityByAccount = new Map<string, MailboxReachabilityRecord>();

  constructor(options: {
    sessions: Pick<SessionStore, "list">;
    repository: InboundEventStateRepository;
    processor: Pick<RealtimeProtectionProcessor, "process">;
    pollProbe?: MailboxCheckpointProbe;
    pollIntervalMs?: number;
    protectionEnabled?: (accountKey: string) => boolean;
  }) {
    this.#sessions = options.sessions;
    this.#pollProbe = options.pollProbe ?? null;
    this.#pollIntervalMs = boundedInterval(options.pollIntervalMs ?? DEFAULT_REALTIME_POLL_INTERVAL_MS);
    this.#protectionEnabled = options.protectionEnabled ?? (() => true);
    this.#coordinator = new InboundProtectionCoordinator({
      repository: options.repository,
      processor: (event) => options.processor.process(event),
    });
  }

  start(): void {
    if (this.#timer) return;
    this.#timer = setInterval(() => { void this.pollNow(); }, this.#pollIntervalMs);
    this.#timer.unref();
    // Establish provider baselines/reachability immediately, but startup never
    // becomes a scan and disabled accounts remain scan-paused.
    void this.pollNow();
  }

  stop(): void {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
  }

  status(): RealtimeProtectionStatus {
    const backlog = this.#coordinator.backlog();
    const connectedAccounts = new Set(
      this.#sessions.list()
        .filter((session) => !session.closing && providerOf(session.provider))
        .map((session) => session.policyAccountKey),
    ).size;
    return {
      running: this.#timer !== null,
      persistentReplayState: this.#coordinator.persistent,
      pollIntervalMs: this.#pollIntervalMs,
      queued: backlog.queued,
      processing: backlog.processing,
      connectedAccounts,
      lastPollAt: this.#lastPollAt,
      lastSuccessAt: this.#lastSuccessAt,
      lastErrorAt: this.#lastErrorAt,
      lastErrorCode: this.#lastErrorCode,
    };
  }

  accountStatus(session: AccountSession): AccountAutomaticProtectionStatus {
    return {
      automaticProcessingEnabled: this.#protectionEnabled(session.policyAccountKey),
      providerEvents: "not_configured_in_desktop_runtime",
      metadataCheckpointFallback: this.#pollProbe ? "available" : "unavailable",
      pollIntervalMs: this.#pollIntervalMs,
      persistentReplayState: this.#coordinator.persistent,
      lastPollAt: this.#lastPollAt,
      lastSuccessAt: this.#lastSuccessAt,
      lastErrorAt: this.#lastErrorAt,
      lastErrorCode: this.#lastErrorCode,
    };
  }

  mailboxReachability(session: AccountSession): MailboxReachabilitySnapshot {
    const record = this.#mailboxReachabilityByAccount.get(session.policyAccountKey);
    if (!record || record.sessionId !== session.id) {
      return { state: "checking", checkedAt: null, lastReachableAt: null };
    }
    return {
      state: record.state,
      checkedAt: record.checkedAt,
      lastReachableAt: record.lastReachableAt,
    };
  }

  #recordMailboxReachability(
    session: AccountSession,
    state: "reachable" | "unavailable",
    checkedAt: number,
  ): void {
    const previous = this.#mailboxReachabilityByAccount.get(session.policyAccountKey);
    const sameSession = previous?.sessionId === session.id;
    this.#mailboxReachabilityByAccount.set(session.policyAccountKey, {
      sessionId: session.id,
      state,
      checkedAt,
      lastReachableAt: state === "reachable"
        ? checkedAt
        : sameSession ? previous.lastReachableAt : null,
    });
  }

  async enqueue(input: CanonicalInboundEventV1): Promise<RealtimeProtectionOutcome> {
    const event = normalizeInboundEvent(input);
    if (!this.#protectionEnabled(event.accountKey)) {
      if (event.checkpoint) this.#coordinator.observeCheckpoint(event.accountKey, event.provider, event.source, event.checkpoint);
      this.#lastErrorCode = null;
      return { status: "disabled" };
    }
    try {
      const outcome = await this.#coordinator.enqueue(event);
      if (outcome.status !== "duplicate") this.#lastSuccessAt = Date.now();
      this.#lastErrorCode = null;
      return outcome;
    } catch (error) {
      this.#recordError(error);
      throw error;
    }
  }

  async enqueueBatch(batch: ProviderInboundBatch): Promise<RealtimeProtectionOutcome[]> {
    const outcomes: RealtimeProtectionOutcome[] = [];
    for (const event of batch.events) outcomes.push(await this.enqueue(event));
    return outcomes;
  }

  async #pollAccount(session: AccountSession, checkedAt: number): Promise<void> {
    const provider = providerOf(session.provider);
    if (!provider || session.closing || !this.#pollProbe) return;

    let checkpoint: string | null;
    try {
      checkpoint = await this.#pollProbe.checkpoint(session);
    } catch {
      this.#recordMailboxReachability(session, "unavailable", checkedAt);
      this.#lastErrorAt = checkedAt;
      this.#lastErrorCode = "provider_unavailable";
      return;
    }
    this.#recordMailboxReachability(session, "reachable", checkedAt);
    if (!checkpoint) return;

    const current = this.#coordinator.checkpoint(session.policyAccountKey, provider, "poll");
    if (current === null) {
      try {
        this.#coordinator.establishCheckpoint(session.policyAccountKey, provider, "poll", checkpoint);
      } catch (error) {
        this.#recordError(error);
      }
      return;
    }
    if (current === checkpoint) return;

    if (!this.#protectionEnabled(session.policyAccountKey)) {
      try {
        this.#coordinator.observeCheckpoint(session.policyAccountKey, provider, "poll", checkpoint);
        this.#lastErrorCode = null;
      } catch (error) {
        this.#recordError(error);
      }
      return;
    }

    try {
      await this.enqueue(pollingEvent(session.policyAccountKey, provider, current, checkpoint));
    } catch {
      // Failed processing must remain unacknowledged so the same checkpoint and
      // event identity are retried on the next poll.
    }
  }

  /**
   * Metadata-only fallback tick. Connected accounts are probed concurrently so
   * a slow or unavailable provider cannot prevent another account from being
   * observed. The probe is permitted while Continuous Protection is paused only
   * for reachability/latest-checkpoint state; it cannot launch a scan.
   */
  async pollNow(now = Date.now()): Promise<void> {
    if (this.#pollRunning) return;
    this.#pollRunning = true;
    try {
      this.#lastPollAt = now;
      if (!this.#pollProbe) return;

      const unique = new Map<string, AccountSession>();
      for (const session of this.#sessions.list()) {
        const provider = providerOf(session.provider);
        if (!provider || session.closing) continue;
        const key = `${provider}\0${session.policyAccountKey}`;
        if (!unique.has(key)) unique.set(key, session);
      }
      await Promise.all([...unique.values()].map((session) => this.#pollAccount(session, now)));
    } finally {
      this.#pollRunning = false;
    }
  }

  #recordError(error: unknown): void {
    this.#lastErrorAt = Date.now();
    const code = error && typeof error === "object" && "code" in error ? String((error as { code?: unknown }).code ?? "") : "";
    this.#lastErrorCode = code === "scan_conflict"
      ? "scan_conflict"
      : code === "provider_unavailable"
        ? "provider_unavailable"
        : code === "provider_mismatch"
          ? "provider_mismatch"
          : "processing_failure";
  }
}
