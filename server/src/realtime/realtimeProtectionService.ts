import { randomUUID } from "node:crypto";
import type { SessionStore } from "../api/sessionStore.js";
import type { Provider } from "../canonical/envelope.js";
import {
  InboundProtectionCoordinator,
  type CanonicalInboundEventV1,
  type InboundEventOutcome,
  type InboundEventStateRepository,
} from "./inboundEvents.js";
import { createPollingFallbackEvent, type ProviderInboundBatch } from "./providerSources.js";
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

interface PollCursor {
  generation: string;
  sequence: number;
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
 * Local near-realtime runtime.
 *
 * Push/IDLE adapters may enqueue normalized events immediately. Polling remains
 * the provider-neutral safety net when push delivery is unavailable, delayed,
 * dropped, or requires public infrastructure. One coordinator serializes all
 * processing so realtime work does not create unbounded Worker concurrency.
 */
export class RealtimeProtectionService {
  readonly #sessions: Pick<SessionStore, "list">;
  readonly #coordinator: InboundProtectionCoordinator;
  readonly #pollIntervalMs: number;
  readonly #pollCursors = new Map<string, PollCursor>();
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
    // Initial protection check is intentionally immediate so app restart does
    // not create a full polling interval of unprotected time.
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
   * Poll every connected account serially. A cursor advances only after the
   * corresponding protection scan succeeds; failures retry the same opaque
   * event identity on the next poll instead of pretending it was handled.
   */
  async pollNow(now = Date.now()): Promise<void> {
    if (this.#pollRunning) return;
    this.#pollRunning = true;
    this.#lastPollAt = now;
    try {
      const seen = new Set<string>();
      const sessions = this.#sessions.list()
        .filter((session) => !session.closing)
        .filter((session) => providerOf(session.provider) !== null)
        .sort((left, right) => left.policyAccountKey.localeCompare(right.policyAccountKey));

      for (const session of sessions) {
        const provider = providerOf(session.provider)!;
        const key = `${session.policyAccountKey}\0${provider}`;
        if (seen.has(key)) {
          // Duplicate active identity is deliberately left to the processor's
          // ambiguity check if an external trigger arrives. Polling itself does
          // not amplify the duplicate into multiple scans.
          continue;
        }
        seen.add(key);
        let cursor = this.#pollCursors.get(key);
        if (!cursor) {
          cursor = { generation: randomUUID(), sequence: 0 };
          this.#pollCursors.set(key, cursor);
        }
        const batch = createPollingFallbackEvent({
          accountKey: session.policyAccountKey,
          provider,
          pollGeneration: cursor.generation,
          sequence: cursor.sequence,
        });
        try {
          await this.enqueueBatch(batch);
          cursor.sequence += 1;
        } catch {
          // Keep the same sequence so the failed trigger is retried next time.
          // Continue to other accounts: one unavailable mailbox must not starve
          // protection for unrelated connected accounts.
        }
      }

      for (const key of [...this.#pollCursors.keys()]) {
        if (!seen.has(key)) this.#pollCursors.delete(key);
      }
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
