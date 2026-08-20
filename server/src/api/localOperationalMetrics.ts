import type { Provider } from "../canonical/envelope.js";
import type { ScanCounters } from "../workflows/scanWorkflows.js";

export type AdapterOperation = "connect" | "list_folders" | "fetch_page" | "move_to_trash" | "report_spam" | "move_to_inbox" | "disconnect";
export type ScanOutcome = "completed" | "failed" | "stopped";

interface MutableAdapterMetric {
  attempts: number;
  succeeded: number;
  failed: number;
  cancelled: number;
  active: number;
  durationMilliseconds: number;
}

interface MutableProviderHealth {
  scansStarted: number;
  scansCompleted: number;
  scansFailed: number;
  scansStopped: number;
  messagesExamined: number;
  verdicts: Omit<ScanCounters, "examined" | "skipped" | "malformed">;
  skipped: number;
  malformed: number;
  operations: Record<AdapterOperation, MutableAdapterMetric>;
}

const PROVIDERS: Provider[] = ["gmail", "icloud", "outlook", "yahoo", "imap"];
const OPERATIONS: AdapterOperation[] = ["connect", "list_folders", "fetch_page", "move_to_trash", "report_spam", "move_to_inbox", "disconnect"];

function adapterMetric(): MutableAdapterMetric {
  return { attempts: 0, succeeded: 0, failed: 0, cancelled: 0, active: 0, durationMilliseconds: 0 };
}

function providerHealth(): MutableProviderHealth {
  return {
    scansStarted: 0,
    scansCompleted: 0,
    scansFailed: 0,
    scansStopped: 0,
    messagesExamined: 0,
    verdicts: { safe: 0, review: 0, highRisk: 0, confirmedThreat: 0, unknown: 0 },
    skipped: 0,
    malformed: 0,
    operations: Object.fromEntries(OPERATIONS.map((operation) => [operation, adapterMetric()])) as Record<AdapterOperation, MutableAdapterMetric>,
  };
}

function boundedWorkerMetric(value: unknown): number {
  if (!Number.isFinite(value) || Number(value) < 0) return 0;
  return Math.min(1_000_000_000, Math.floor(Number(value)));
}

export function cancelledOperationalError(error: unknown): boolean {
  return error instanceof Error && error.name === "AbortError";
}

/** Process-local, fixed-cardinality counters. No method accepts labels or content. */
export class LocalOperationalMetrics {
  private readonly startedAt: number;
  private readonly providers = new Map<Provider, MutableProviderHealth>();
  private falsePositiveApprovals = 0;
  private abuseReportsAccepted = 0;
  private abuseReportsFailed = 0;

  constructor(private readonly now: () => number = Date.now) {
    this.startedAt = now();
    for (const provider of PROVIDERS) this.providers.set(provider, providerHealth());
  }

  beginAdapterOperation(provider: Provider, operation: AdapterOperation): (outcome: "succeeded" | "failed" | "cancelled") => void {
    const metric = this.providers.get(provider)!.operations[operation];
    metric.attempts += 1;
    metric.active += 1;
    const startedAt = this.now();
    let finished = false;
    return (outcome) => {
      if (finished) return;
      finished = true;
      metric.active = Math.max(0, metric.active - 1);
      metric.durationMilliseconds += Math.max(0, this.now() - startedAt);
      if (outcome === "succeeded") metric.succeeded += 1;
      else if (outcome === "cancelled") metric.cancelled += 1;
      else metric.failed += 1;
    };
  }

  recordScanStarted(provider: Provider): void {
    this.providers.get(provider)!.scansStarted += 1;
  }

  recordScanFinished(provider: Provider, outcome: ScanOutcome, counters: ScanCounters): void {
    const health = this.providers.get(provider)!;
    if (outcome === "completed") health.scansCompleted += 1;
    else if (outcome === "stopped") health.scansStopped += 1;
    else health.scansFailed += 1;
    health.messagesExamined += Math.max(0, counters.examined);
    health.verdicts.safe += Math.max(0, counters.safe);
    health.verdicts.review += Math.max(0, counters.review);
    health.verdicts.highRisk += Math.max(0, counters.highRisk);
    health.verdicts.confirmedThreat += Math.max(0, counters.confirmedThreat);
    health.verdicts.unknown += Math.max(0, counters.unknown);
    health.skipped += Math.max(0, counters.skipped);
    health.malformed += Math.max(0, counters.malformed);
  }

  /**
   * Worker threads own separate module instances, so adapter counters recorded
   * inside scan/Health workers must be merged explicitly into this main-process
   * owner. Only fixed-cardinality aggregate operation counters are accepted;
   * active gauges, labels and content are intentionally ignored.
   */
  mergeWorkerAdapterSnapshot(snapshot: unknown): void {
    if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) return;
    const root = snapshot as { schemaVersion?: unknown; providers?: unknown };
    if (root.schemaVersion !== 1 || !root.providers || typeof root.providers !== "object" || Array.isArray(root.providers)) return;
    const providerRecord = root.providers as Record<string, unknown>;
    for (const provider of PROVIDERS) {
      const candidate = providerRecord[provider];
      if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) continue;
      const operations = (candidate as { operations?: unknown }).operations;
      if (!operations || typeof operations !== "object" || Array.isArray(operations)) continue;
      const operationRecord = operations as Record<string, unknown>;
      for (const operation of OPERATIONS) {
        const workerMetric = operationRecord[operation];
        if (!workerMetric || typeof workerMetric !== "object" || Array.isArray(workerMetric)) continue;
        const raw = workerMetric as Record<string, unknown>;
        const metric = this.providers.get(provider)!.operations[operation];
        metric.attempts += boundedWorkerMetric(raw.attempts);
        metric.succeeded += boundedWorkerMetric(raw.succeeded);
        metric.failed += boundedWorkerMetric(raw.failed);
        metric.cancelled += boundedWorkerMetric(raw.cancelled);
        metric.durationMilliseconds += boundedWorkerMetric(raw.durationMilliseconds);
      }
    }
  }

  recordFalsePositiveApproval(): void { this.falsePositiveApprovals += 1; }
  recordAbuseReport(accepted: boolean): void {
    if (accepted) this.abuseReportsAccepted += 1;
    else this.abuseReportsFailed += 1;
  }

  snapshot() {
    return {
      schemaVersion: 1 as const,
      scope: "current_process" as const,
      uptimeSeconds: Math.max(0, (this.now() - this.startedAt) / 1000),
      providers: Object.fromEntries(PROVIDERS.map((provider) => {
        const health = this.providers.get(provider)!;
        return [provider, {
          scans: {
            started: health.scansStarted,
            completed: health.scansCompleted,
            failed: health.scansFailed,
            stopped: health.scansStopped,
          },
          messages: {
            examined: health.messagesExamined,
            ...health.verdicts,
            skipped: health.skipped,
            malformed: health.malformed,
          },
          operations: Object.fromEntries(OPERATIONS.map((operation) => [operation, { ...health.operations[operation] }])),
        }];
      })),
      review: {
        falsePositiveApprovals: this.falsePositiveApprovals,
        abuseReportsAccepted: this.abuseReportsAccepted,
        abuseReportsFailed: this.abuseReportsFailed,
      },
    };
  }
}

export const localOperationalMetrics = new LocalOperationalMetrics();
