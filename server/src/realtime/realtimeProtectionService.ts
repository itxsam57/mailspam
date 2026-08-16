import type { SessionStore } from "../api/sessionStore.js";
import type { Provider } from "../canonical/envelope.js";
import {
  InboundProtectionCoordinator,
  type CanonicalInboundEventV1,
  type InboundEventOutcome,
  type InboundEventStateRepository,
} from "./inboundEvents.js";
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

/**
 * Local near-realtime event coordinator.
 *
 * Provider push/IDLE adapters may enqueue normalized metadata-only events
 * immediately. The local timer is housekeeping only: without a trusted provider
 * change signal it must never invent a mailbox change or launch a Quick scan.
 * Scheduled Background Protection remains the provider-neutral fallback when a
 * live source is not wired or available.
 */
export class RealtimeProtectionService {
  readonly #sessions: Pick<SessionStore, "list">;
  readonly #coordinator: InboundProtectionCoordinator;
  readonly #pollIntervalMs: number;
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
    pollIntervalMs?: number;
  }) {
    this.#sessions = options.sessions;
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
    // Record startup housekeeping immediately. Actual protection work requires
    // either a trusted provider event or a due Background Protection schedule.
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

  /**
   * Lightweight housekeeping tick. This intentionally does not synthesize a
   * `mailbox_changed` event: an idle clock tick is not evidence that mail
   * changed. Provider-specific source owners must enqueue a trusted normalized
   * event when they observe a real change.
   */
  async pollNow(now = Date.now()): Promise<void> {
    if (this.#pollRunning) return;
    this.#pollRunning = true;
    try {
      this.#lastPollAt = now;
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
