import { createHmac, randomBytes } from "node:crypto";
import type { CanonicalEnvelope } from "../canonical/envelope.js";
import { classifyDestination, type DestinationResult } from "../engine/layers/destinationClassification.js";
import { hardenedFetch, type HardenedFetchResult } from "../util/hardenedFetch.js";

export const DESTINATION_ANALYSIS_CONCURRENCY = 4;
export const MAX_DESTINATION_ANALYSIS_QUEUE = 256;
export const MAX_DESTINATION_CACHE_ENTRIES = 512;
export const DESTINATION_CACHE_TTL_MS = 5 * 60 * 1000;
export const DESTINATION_ERROR_CACHE_TTL_MS = 15 * 1000;

export type DestinationFetch = (url: string) => Promise<HardenedFetchResult | null>;
type CachedDestinationResult = Omit<DestinationResult, "url">;

export interface AnalyzeLinksResult {
  results: DestinationResult[];
  /** Escalation: even if the scan-time verdict was "review", a credential trap here bumps the user-facing state. */
  escalatedToHighRisk: boolean;
}

export interface DestinationAnalysisTelemetry {
  activeWorkers: number;
  queuedJobs: number;
  inFlightDestinations: number;
  cachedDestinations: number;
  cacheHits: number;
  cacheMisses: number;
  coalescedRequests: number;
  rejectedJobs: number;
  evictedEntries: number;
}

export interface DestinationAnalysisCoordinatorOptions {
  fetchImpl: DestinationFetch;
  concurrency?: number;
  maxQueue?: number;
  maxCacheEntries?: number;
  cacheTtlMs?: number;
  errorCacheTtlMs?: number;
  now?: () => number;
  cacheKey?: Buffer;
}

interface CacheEntry {
  expiresAt: number;
  result: CachedDestinationResult;
}

interface QueuedJob {
  run(): Promise<void>;
}

const CAPACITY_RESULT: CachedDestinationResult = {
  classification: "error",
  hasForm: false,
  hasPasswordField: false,
  detail: "Destination analysis capacity is currently exhausted; the destination was not treated as benign.",
};

const INTERNAL_ERROR_RESULT: CachedDestinationResult = {
  classification: "error",
  hasForm: false,
  hasPasswordField: false,
  detail: "Destination analysis failed without a trusted result; the destination was not treated as benign.",
};

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${name} must be a positive safe integer.`);
  return value;
}

function positiveDuration(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new Error(`${name} must be a positive duration.`);
  return value;
}

function withoutUrl(result: DestinationResult): CachedDestinationResult {
  return {
    classification: result.classification,
    hasForm: result.hasForm,
    hasPasswordField: result.hasPasswordField,
    detail: result.detail,
  };
}

function withUrl(url: string, result: CachedDestinationResult): DestinationResult {
  return { url, ...result };
}

/**
 * Process-wide coordinator for the explicit Analyze Links action.
 *
 * It is deliberately separate from automatic mailbox scans. A fixed worker
 * pool is the only path to the DNS-pinned fetcher, the waiting queue is
 * bounded, identical in-flight destinations are coalesced, and completed
 * classifications use a fixed-expiry bounded LRU cache. Cache keys are
 * process-random HMACs and cached values contain neither a URL nor fetched
 * page content. Nothing in this coordinator is written to disk.
 */
export class DestinationAnalysisCoordinator {
  private readonly fetchImpl: DestinationFetch;
  private readonly concurrency: number;
  private readonly maxQueue: number;
  private readonly maxCacheEntries: number;
  private readonly cacheTtlMs: number;
  private readonly errorCacheTtlMs: number;
  private readonly now: () => number;
  private readonly cacheKey: Buffer;
  private readonly queue: QueuedJob[] = [];
  private readonly cache = new Map<string, CacheEntry>();
  private readonly inFlight = new Map<string, Promise<CachedDestinationResult>>();
  private activeWorkers = 0;
  private counters = {
    cacheHits: 0,
    cacheMisses: 0,
    coalescedRequests: 0,
    rejectedJobs: 0,
    evictedEntries: 0,
  };

  constructor(options: DestinationAnalysisCoordinatorOptions) {
    this.fetchImpl = options.fetchImpl;
    this.concurrency = positiveInteger(options.concurrency ?? DESTINATION_ANALYSIS_CONCURRENCY, "concurrency");
    this.maxQueue = positiveInteger(options.maxQueue ?? MAX_DESTINATION_ANALYSIS_QUEUE, "maxQueue");
    this.maxCacheEntries = positiveInteger(options.maxCacheEntries ?? MAX_DESTINATION_CACHE_ENTRIES, "maxCacheEntries");
    this.cacheTtlMs = positiveDuration(options.cacheTtlMs ?? DESTINATION_CACHE_TTL_MS, "cacheTtlMs");
    this.errorCacheTtlMs = positiveDuration(options.errorCacheTtlMs ?? DESTINATION_ERROR_CACHE_TTL_MS, "errorCacheTtlMs");
    this.now = options.now ?? Date.now;
    this.cacheKey = Buffer.from(options.cacheKey ?? randomBytes(32));
    if (this.cacheKey.length !== 32) throw new Error("cacheKey must contain exactly 32 bytes.");
  }

  async analyze(envelope: CanonicalEnvelope): Promise<AnalyzeLinksResult> {
    const results = await Promise.all(
      envelope.links.map((link) => this.analyzeDestination(link.normalizedUrl)),
    );
    const escalatedToHighRisk = results.some(
      (result) => result.classification === "credential_trap" || result.classification === "malware",
    );
    return { results, escalatedToHighRisk };
  }

  telemetry(): DestinationAnalysisTelemetry {
    this.pruneExpired();
    return {
      activeWorkers: this.activeWorkers,
      queuedJobs: this.queue.length,
      inFlightDestinations: this.inFlight.size,
      cachedDestinations: this.cache.size,
      ...this.counters,
    };
  }

  clearCache(): void {
    this.cache.clear();
  }

  private async analyzeDestination(url: string): Promise<DestinationResult> {
    const token = this.tokenFor(url);
    const cached = this.readCache(token);
    if (cached) {
      this.counters.cacheHits += 1;
      return withUrl(url, cached);
    }

    const existing = this.inFlight.get(token);
    if (existing) {
      this.counters.coalescedRequests += 1;
      return withUrl(url, await existing);
    }

    this.counters.cacheMisses += 1;
    if (this.activeWorkers >= this.concurrency && this.queue.length >= this.maxQueue) {
      this.counters.rejectedJobs += 1;
      return withUrl(url, CAPACITY_RESULT);
    }

    const pending = this.enqueue(async () => {
      try {
        return withoutUrl(await classifyDestination(url, this.fetchImpl));
      } catch {
        return INTERNAL_ERROR_RESULT;
      }
    });
    this.inFlight.set(token, pending);

    try {
      const result = await pending;
      this.writeCache(token, result);
      return withUrl(url, result);
    } finally {
      this.inFlight.delete(token);
    }
  }

  private tokenFor(url: string): string {
    return createHmac("sha256", this.cacheKey).update(url, "utf8").digest("base64url");
  }

  private readCache(token: string): CachedDestinationResult | null {
    const entry = this.cache.get(token);
    if (!entry) return null;
    if (entry.expiresAt <= this.now()) {
      this.cache.delete(token);
      return null;
    }
    // Map insertion order is the LRU order. Expiry remains fixed and is not
    // extended by reads, so retention cannot become unbounded through traffic.
    this.cache.delete(token);
    this.cache.set(token, entry);
    return entry.result;
  }

  private writeCache(token: string, result: CachedDestinationResult): void {
    this.pruneExpired();
    this.cache.delete(token);
    const ttl = result.classification === "error" ? this.errorCacheTtlMs : this.cacheTtlMs;
    this.cache.set(token, { expiresAt: this.now() + ttl, result: { ...result } });
    while (this.cache.size > this.maxCacheEntries) {
      const oldest = this.cache.keys().next().value as string | undefined;
      if (!oldest) break;
      this.cache.delete(oldest);
      this.counters.evictedEntries += 1;
    }
  }

  private pruneExpired(): void {
    const now = this.now();
    for (const [token, entry] of this.cache) {
      if (entry.expiresAt <= now) this.cache.delete(token);
    }
  }

  private enqueue(work: () => Promise<CachedDestinationResult>): Promise<CachedDestinationResult> {
    const pending = new Promise<CachedDestinationResult>((resolve) => {
      this.queue.push({
        run: async () => {
          try {
            resolve(await work());
          } finally {
            this.activeWorkers -= 1;
            this.drain();
          }
        },
      });
    });
    this.drain();
    return pending;
  }

  private drain(): void {
    while (this.activeWorkers < this.concurrency) {
      const job = this.queue.shift();
      if (!job) return;
      this.activeWorkers += 1;
      void job.run();
    }
  }
}

export function createDestinationAnalysisCoordinator(
  options: Partial<DestinationAnalysisCoordinatorOptions> & Pick<DestinationAnalysisCoordinatorOptions, "fetchImpl">,
): DestinationAnalysisCoordinator {
  return new DestinationAnalysisCoordinator(options);
}

export const destinationAnalysisCoordinator = createDestinationAnalysisCoordinator({ fetchImpl: hardenedFetch });

/** Explicit per-message action only; never called automatically during any scan. */
export async function analyzeLinks(
  envelope: CanonicalEnvelope,
  coordinator: DestinationAnalysisCoordinator = destinationAnalysisCoordinator,
): Promise<AnalyzeLinksResult> {
  return coordinator.analyze(envelope);
}
