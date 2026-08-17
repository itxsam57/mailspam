import type { AccountSession, SessionStore } from "../api/sessionStore.js";
import type { Provider } from "../canonical/envelope.js";
import { sha256Hex } from "../core/sha256.js";
import {
  InboundProtectionCoordinator,
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
 * path only after the checkpoint genuinely changes.
 */
export class RealtimeProtectionService {
  readonly #sessions: Pick<SessionStore, "list">;
  readonly #coordinator: InboundProtectionCoordinator;
  readonly #pollIntervalMs: number;
  readonly #pollProbe: MailboxCheckpointProbe | null;
  #timer: NodeJS.Timeout | null = null;
  #pollRunning = false;
  #lastPollAt: number | null = null;
  #lastSuccessAt: number | null = null;
  #lastErrorAt: number | null = null;
  #lastErrorCode: RealtimeProtectionStatus["lastErrorCode"] = null;

  constructor(options: {
    sessions: Pick<SessionStore, "list">;
    repository: InboundEventStateRepository;
    processor: Pick<RealtimeProtectionProcessor, "process">;
    pollProbe?: MailboxCheckpointProbe;
    pollIntervalMs?: number;
  }) {
    this.#sessions = options.sessions;
    this.#pollProbe = options.pollProbe ?? null;
    this.#pollIntervalMs = boundedInterval(options.pollIntervalMs ?? DEFAULT_REALTIME_POLL_INTERVAL_MS);
    this.#coordinator = new InboundProtectionCoordinator({
      repository: options.repository,
      processor: (event) => options.processor.process(event),
    });
  }

  start(): void {
    if (this.#timer) return;
    this.#timer = setInterval(() => { void this.pollNow(); }, this.#pollIntervalMs);
    this.#timer.unref();
    // Establish provider baselines immediately, but never turn startup itself
    // into a scan or Activity entry.
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

  async enqueue(event: CanonicalInboundEventV1): Promise<InboundEventOutcome> {
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

  async enqueueBatch(batch: ProviderInboundBatch): Promise<InboundEventOutcome[]> {
    const outcomes: InboundEventOutcome[] = [];
    for (const event of batch.events) outcomes.push(await this.enqueue(event));
    return outcomes;
  }

  async #pollAccount(session: AccountSession): Promise<void> {
    const provider = providerOf(session.provider);
    if (!provider || session.closing || !this.#pollProbe) return;

    let checkpoint: string | null;
    try {
      checkpoint = await this.#pollProbe.checkpoint(session);
    } catch {
      this.#lastErrorAt = Date.now();
      this.#lastErrorCode = "provider_unavailable";
      return;
    }
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
   * protected. The shared inbound coordinator still serializes actual scans.
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
      await Promise.all([...unique.values()].map((session) => this.#pollAccount(session)));
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
