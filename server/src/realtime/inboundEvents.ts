import type { Provider } from "../canonical/envelope.js";
import { sha256Hex } from "../core/sha256.js";

export const INBOUND_EVENT_SCHEMA_VERSION = 1;
export const MAX_INBOUND_EVENT_ID_CHARS = 4096;
export const MAX_INBOUND_CHECKPOINT_CHARS = 8192;
export const MAX_INBOUND_ACCOUNT_KEY_CHARS = 512;
export const DEFAULT_MAX_PENDING_INBOUND_EVENTS = 256;
export const DEFAULT_MAX_REMEMBERED_INBOUND_EVENTS = 8192;

export type InboundEventSource = "push" | "idle" | "poll";
export type InboundEventKind = "mailbox_changed" | "message_arrived";

export interface CanonicalInboundEventV1 {
  schemaVersion: 1;
  accountKey: string;
  provider: Provider;
  source: InboundEventSource;
  kind: InboundEventKind;
  /** Provider/source-specific id used only to make delivery replay-safe. */
  eventId: string;
  /** Optional provider change/history checkpoint; local protected state only. */
  checkpoint?: string | null;
  /** Optional provider-native message id. The generic coordinator never persists it. */
  providerMessageId?: string | null;
}

export interface InboundEventStateV1 {
  schemaVersion: 1;
  /** SHA-256 replay keys only; no raw event/message ids. Oldest first. */
  rememberedEventKeys: string[];
  /** Provider checkpoints are local state and must use an encrypted repository in production. */
  checkpoints: Record<string, string>;
}

export interface InboundEventStateRepository {
  readonly persistent: boolean;
  load(): InboundEventStateV1;
  save(state: InboundEventStateV1): void;
}

export class InMemoryInboundEventStateRepository implements InboundEventStateRepository {
  readonly persistent = false;
  #state: InboundEventStateV1;

  constructor(initial?: InboundEventStateV1) {
    this.#state = initial ? cloneState(initial) : emptyInboundEventState();
  }

  load(): InboundEventStateV1 {
    return cloneState(this.#state);
  }

  save(state: InboundEventStateV1): void {
    this.#state = cloneState(state);
  }
}

export interface InboundEventProcessingResult {
  examined: number;
  warnings: number;
  highRisk: number;
  confirmedThreat: number;
}

export type InboundEventProcessor = (
  event: Readonly<CanonicalInboundEventV1>,
) => Promise<InboundEventProcessingResult>;

export type InboundEventOutcome =
  | { status: "processed"; result: InboundEventProcessingResult }
  | { status: "duplicate" }
  | { status: "coalesced"; result: InboundEventProcessingResult };

export class InboundEventBacklogError extends Error {
  constructor() {
    super("Real-time protection backlog is full; the source must retry or rely on scheduled protection.");
    this.name = "InboundEventBacklogError";
  }
}

export class InvalidInboundEventError extends Error {
  constructor(message = "Inbound protection event is invalid.") {
    super(message);
    this.name = "InvalidInboundEventError";
  }
}

interface PendingItem {
  event: CanonicalInboundEventV1;
  replayKey: string;
  resolve: (outcome: InboundEventOutcome) => void;
  reject: (error: unknown) => void;
}

function emptyInboundEventState(): InboundEventStateV1 {
  return { schemaVersion: INBOUND_EVENT_SCHEMA_VERSION, rememberedEventKeys: [], checkpoints: {} };
}

function cloneState(state: InboundEventStateV1): InboundEventStateV1 {
  if (state.schemaVersion !== INBOUND_EVENT_SCHEMA_VERSION
    || !Array.isArray(state.rememberedEventKeys)
    || state.rememberedEventKeys.some((value) => typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value))
    || !state.checkpoints
    || typeof state.checkpoints !== "object"
    || Array.isArray(state.checkpoints)
    || Object.entries(state.checkpoints).some(([key, value]) => !key || typeof value !== "string" || value.length > MAX_INBOUND_CHECKPOINT_CHARS)) {
    throw new InvalidInboundEventError("Inbound event replay state is invalid.");
  }
  return {
    schemaVersion: INBOUND_EVENT_SCHEMA_VERSION,
    rememberedEventKeys: [...state.rememberedEventKeys],
    checkpoints: { ...state.checkpoints },
  };
}

function normalizedString(value: unknown, maxChars: number, field: string): string {
  if (typeof value !== "string") throw new InvalidInboundEventError(`${field} must be a string.`);
  const normalized = value.trim();
  if (!normalized || normalized.length > maxChars) throw new InvalidInboundEventError(`${field} is outside the accepted bounds.`);
  return normalized;
}

const PROVIDERS = new Set<Provider>(["gmail", "icloud", "outlook", "yahoo", "imap"]);
const SOURCES = new Set<InboundEventSource>(["push", "idle", "poll"]);
const KINDS = new Set<InboundEventKind>(["mailbox_changed", "message_arrived"]);

export function normalizeInboundEvent(input: unknown): CanonicalInboundEventV1 {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new InvalidInboundEventError();
  const record = input as Record<string, unknown>;
  const allowed = new Set(["schemaVersion", "accountKey", "provider", "source", "kind", "eventId", "checkpoint", "providerMessageId"]);
  if (Object.keys(record).some((key) => !allowed.has(key)) || record.schemaVersion !== INBOUND_EVENT_SCHEMA_VERSION) {
    throw new InvalidInboundEventError();
  }
  if (!PROVIDERS.has(record.provider as Provider)
    || !SOURCES.has(record.source as InboundEventSource)
    || !KINDS.has(record.kind as InboundEventKind)) {
    throw new InvalidInboundEventError();
  }
  const checkpoint = record.checkpoint === undefined || record.checkpoint === null
    ? null
    : normalizedString(record.checkpoint, MAX_INBOUND_CHECKPOINT_CHARS, "checkpoint");
  const providerMessageId = record.providerMessageId === undefined || record.providerMessageId === null
    ? null
    : normalizedString(record.providerMessageId, MAX_INBOUND_EVENT_ID_CHARS, "providerMessageId");
  return {
    schemaVersion: INBOUND_EVENT_SCHEMA_VERSION,
    accountKey: normalizedString(record.accountKey, MAX_INBOUND_ACCOUNT_KEY_CHARS, "accountKey"),
    provider: record.provider as Provider,
    source: record.source as InboundEventSource,
    kind: record.kind as InboundEventKind,
    eventId: normalizedString(record.eventId, MAX_INBOUND_EVENT_ID_CHARS, "eventId"),
    checkpoint,
    providerMessageId,
  };
}

function replayKey(event: CanonicalInboundEventV1): string {
  // The raw provider event/message id never enters durable replay state.
  return sha256Hex([
    "email-shield-inbound-event-v1",
    event.accountKey,
    event.provider,
    event.source,
    event.kind,
    event.eventId,
  ].join("\0"));
}

function checkpointKey(event: CanonicalInboundEventV1): string {
  return sha256Hex(`email-shield-inbound-checkpoint-v1\0${event.accountKey}\0${event.provider}\0${event.source}`);
}

/**
 * Serial replay-safe coordinator for provider arrival/change signals.
 *
 * It intentionally knows nothing about Gmail/Graph/IMAP transports or verdict
 * scoring. Sources normalize to CanonicalInboundEventV1; the injected processor
 * reuses the existing mailbox scan/protection path. Failed processing is never
 * acknowledged or remembered, so provider retry/scheduled fallback remains safe.
 */
export class InboundProtectionCoordinator {
  readonly #repository: InboundEventStateRepository;
  readonly #processor: InboundEventProcessor;
  readonly #maxPending: number;
  readonly #maxRemembered: number;
  #state: InboundEventStateV1;
  #remembered: Set<string>;
  #pending: PendingItem[] = [];
  #active = false;
  #inFlight = new Map<string, Promise<InboundEventProcessingResult>>();

  constructor(options: {
    repository: InboundEventStateRepository;
    processor: InboundEventProcessor;
    maxPending?: number;
    maxRemembered?: number;
  }) {
    this.#repository = options.repository;
    this.#processor = options.processor;
    this.#maxPending = boundedPositiveInteger(options.maxPending ?? DEFAULT_MAX_PENDING_INBOUND_EVENTS, 1, 4096, "maxPending");
    this.#maxRemembered = boundedPositiveInteger(options.maxRemembered ?? DEFAULT_MAX_REMEMBERED_INBOUND_EVENTS, 64, 65_536, "maxRemembered");
    this.#state = cloneState(this.#repository.load());
    if (this.#state.rememberedEventKeys.length > this.#maxRemembered) {
      this.#state.rememberedEventKeys = this.#state.rememberedEventKeys.slice(-this.#maxRemembered);
      this.#repository.save(this.#state);
    }
    this.#remembered = new Set(this.#state.rememberedEventKeys);
  }

  get persistent(): boolean {
    return this.#repository.persistent;
  }

  backlog(): { queued: number; processing: number; maxPending: number } {
    return { queued: this.#pending.length, processing: this.#active ? 1 : 0, maxPending: this.#maxPending };
  }

  checkpoint(accountKey: string, provider: Provider, source: InboundEventSource): string | null {
    const normalized = normalizeInboundEvent({
      schemaVersion: 1,
      accountKey,
      provider,
      source,
      kind: "mailbox_changed",
      eventId: "checkpoint-query",
    });
    return this.#state.checkpoints[checkpointKey(normalized)] ?? null;
  }

  establishCheckpoint(accountKey: string, provider: Provider, source: InboundEventSource, checkpoint: string): string {
    const normalized = normalizeInboundEvent({
      schemaVersion: 1,
      accountKey,
      provider,
      source,
      kind: "mailbox_changed",
      eventId: "checkpoint-baseline",
      checkpoint,
    });
    const key = checkpointKey(normalized);
    const existing = this.#state.checkpoints[key];
    if (existing) return existing;
    const next = cloneState(this.#state);
    next.checkpoints[key] = normalized.checkpoint!;
    this.#repository.save(next);
    this.#state = next;
    return normalized.checkpoint!;
  }

  /**
   * Records the latest trusted provider checkpoint without acknowledging or
   * executing an inbound event. Continuous Protection uses this while disabled
   * so reachability/change observation cannot later be replayed as a scan for
   * mail that arrived during an explicitly paused period.
   */
  observeCheckpoint(accountKey: string, provider: Provider, source: InboundEventSource, checkpoint: string): string {
    const normalized = normalizeInboundEvent({
      schemaVersion: 1,
      accountKey,
      provider,
      source,
      kind: "mailbox_changed",
      eventId: "checkpoint-observation",
      checkpoint,
    });
    const key = checkpointKey(normalized);
    const next = cloneState(this.#state);
    next.checkpoints[key] = normalized.checkpoint!;
    this.#repository.save(next);
    this.#state = next;
    return normalized.checkpoint!;
  }

  async enqueue(input: unknown): Promise<InboundEventOutcome> {
    const event = normalizeInboundEvent(input);
    const key = replayKey(event);
    if (this.#remembered.has(key)) return { status: "duplicate" };

    const inFlight = this.#inFlight.get(key);
    if (inFlight) return { status: "coalesced", result: await inFlight };
    if (this.#pending.some((item) => item.replayKey === key)) {
      const pendingResult = new Promise<InboundEventProcessingResult>((resolve, reject) => {
        const original = this.#pending.find((item) => item.replayKey === key)!;
        const originalResolve = original.resolve;
        const originalReject = original.reject;
        original.resolve = (outcome) => {
          originalResolve(outcome);
          if (outcome.status === "processed" || outcome.status === "coalesced") resolve(outcome.result);
          else reject(new Error("Duplicate event completed without a processing result."));
        };
        original.reject = (error) => { originalReject(error); reject(error); };
      });
      return { status: "coalesced", result: await pendingResult };
    }
    if (this.#pending.length + (this.#active ? 1 : 0) >= this.#maxPending) throw new InboundEventBacklogError();

    return await new Promise<InboundEventOutcome>((resolve, reject) => {
      this.#pending.push({ event, replayKey: key, resolve, reject });
      void this.#drain();
    });
  }

  #commitSuccess(event: CanonicalInboundEventV1, key: string): void {
    const next = cloneState(this.#state);
    if (!this.#remembered.has(key)) {
      next.rememberedEventKeys.push(key);
      while (next.rememberedEventKeys.length > this.#maxRemembered) next.rememberedEventKeys.shift();
    }
    if (event.checkpoint) next.checkpoints[checkpointKey(event)] = event.checkpoint;

    // Durable acknowledgement is the transaction boundary. Never publish a
    // replay key or checkpoint to the live coordinator until protected state
    // accepts the complete next snapshot; otherwise a failed save could make a
    // later retry look like an already-acknowledged duplicate.
    this.#repository.save(next);
    this.#state = next;
    this.#remembered = new Set(next.rememberedEventKeys);
  }

  async #drain(): Promise<void> {
    if (this.#active) return;
    this.#active = true;
    try {
      while (this.#pending.length) {
        const item = this.#pending.shift()!;
        if (this.#remembered.has(item.replayKey)) {
          item.resolve({ status: "duplicate" });
          continue;
        }
        const processing = this.#processor(Object.freeze({ ...item.event }));
        this.#inFlight.set(item.replayKey, processing);
        try {
          const result = await processing;
          validateProcessingResult(result);
          this.#commitSuccess(item.event, item.replayKey);
          item.resolve({ status: "processed", result: { ...result } });
        } catch (error) {
          item.reject(error);
        } finally {
          this.#inFlight.delete(item.replayKey);
        }
      }
    } finally {
      this.#active = false;
      if (this.#pending.length) void this.#drain();
    }
  }
}

function boundedPositiveInteger(value: number, min: number, max: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new InvalidInboundEventError(`${field} is invalid.`);
  return value;
}

function validateProcessingResult(result: InboundEventProcessingResult): void {
  if (!result || typeof result !== "object") throw new InvalidInboundEventError("Inbound processor returned an invalid result.");
  for (const value of [result.examined, result.warnings, result.highRisk, result.confirmedThreat]) {
    if (!Number.isSafeInteger(value) || value < 0) throw new InvalidInboundEventError("Inbound processor returned invalid counters.");
  }
  if (result.warnings + result.highRisk + result.confirmedThreat > result.examined) {
    throw new InvalidInboundEventError("Inbound processor counters are inconsistent.");
  }
}
