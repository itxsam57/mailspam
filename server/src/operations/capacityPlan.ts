import {
  MAX_COMMUNITY_AUTHORITATIVE_SOURCE_BYTES,
  MAX_COMMUNITY_FEED_ENTRIES,
  MAX_COMMUNITY_FEED_RESPONSE_BYTES,
  MAX_COMMUNITY_REPORT_JOURNAL_BYTES,
  MAX_COMMUNITY_REPORT_REQUEST_BYTES,
} from "../community/resourceLimits.js";
import {
  DESTINATION_ANALYSIS_CONCURRENCY,
  MAX_DESTINATION_ANALYSIS_QUEUE,
  MAX_DESTINATION_CACHE_ENTRIES,
} from "../workflows/analyzeLinks.js";
import {
  MAX_BACKGROUND_INTERVAL_MINUTES,
  MIN_BACKGROUND_INTERVAL_MINUTES,
} from "../api/backgroundProtectionPersistence.js";

export const CAPACITY_PLAN_SCHEMA_VERSION = 1 as const;
export const COST_MONTH_DAYS = 30;
export const COST_MONTH_HOURS = 730;

export interface CapacityWorkloadV1 {
  schemaVersion: 1;
  clients: number;
  averageReportsPerClientPerDay: number;
  retentionDays: number;
  averageReportBytes: number;
  feedDownloadsPerClientPerDay: number;
  averageFeedBytes: number;
  computeInstances: number;
  backupCopies: number;
}

export interface CapacityUnitPrices {
  computeInstanceHour: number;
  storageGibMonth: number;
  egressGib: number;
  requestMillion: number;
}

function finiteRange(value: unknown, minimum: number, maximum: number, name: string, integer = false): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < minimum || value > maximum || (integer && !Number.isSafeInteger(value))) {
    throw new Error(`${name} must be ${integer ? "a whole number" : "a finite number"} between ${minimum} and ${maximum}.`);
  }
  return value;
}

export function assertCapacityWorkload(input: unknown): asserts input is CapacityWorkloadV1 {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Capacity workload must be an object.");
  const value = input as Record<string, unknown>;
  const keys = [
    "schemaVersion", "clients", "averageReportsPerClientPerDay", "retentionDays", "averageReportBytes",
    "feedDownloadsPerClientPerDay", "averageFeedBytes", "computeInstances", "backupCopies",
  ];
  if (Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key)) || value.schemaVersion !== 1) {
    throw new Error("Capacity workload schema is invalid.");
  }
  finiteRange(value.clients, 1, 1_000_000, "clients", true);
  finiteRange(value.averageReportsPerClientPerDay, 0, 50, "averageReportsPerClientPerDay");
  finiteRange(value.retentionDays, 1, 90, "retentionDays", true);
  finiteRange(value.averageReportBytes, 1, MAX_COMMUNITY_REPORT_REQUEST_BYTES, "averageReportBytes", true);
  finiteRange(value.feedDownloadsPerClientPerDay, 0, 48, "feedDownloadsPerClientPerDay");
  finiteRange(value.averageFeedBytes, 1, MAX_COMMUNITY_FEED_RESPONSE_BYTES, "averageFeedBytes", true);
  finiteRange(value.computeInstances, 1, 1_000, "computeInstances", true);
  finiteRange(value.backupCopies, 1, 365, "backupCopies", true);
}

function assertPrices(prices: CapacityUnitPrices): void {
  for (const [name, value] of Object.entries(prices)) finiteRange(value, 0, 1_000_000, name);
}

function gib(bytes: number): number { return bytes / (1024 ** 3); }
function round(value: number): number { return Math.round(value * 1_000_000) / 1_000_000; }

/** Deterministic sizing arithmetic only; it does not claim a throughput SLA. */
export function buildCapacityPlan(workload: CapacityWorkloadV1, prices: CapacityUnitPrices | null = null) {
  assertCapacityWorkload(workload);
  if (prices) assertPrices(prices);
  const dailyReports = workload.clients * workload.averageReportsPerClientPerDay;
  const monthlyRequests = dailyReports * COST_MONTH_DAYS;
  const monthlyIngestBytes = monthlyRequests * workload.averageReportBytes;
  const monthlyFeedEgressBytes = workload.clients * workload.feedDownloadsPerClientPerDay * COST_MONTH_DAYS * workload.averageFeedBytes;
  const projectedRetainedReportPayloadBytes = dailyReports * workload.retentionDays * workload.averageReportBytes;
  const provisionedStorageBytes = MAX_COMMUNITY_AUTHORITATIVE_SOURCE_BYTES * (1 + workload.backupCopies);
  const usageRatio = projectedRetainedReportPayloadBytes / MAX_COMMUNITY_AUTHORITATIVE_SOURCE_BYTES;
  const cost = prices ? {
    compute: workload.computeInstances * COST_MONTH_HOURS * prices.computeInstanceHour,
    storage: gib(provisionedStorageBytes) * prices.storageGibMonth,
    egress: gib(monthlyFeedEgressBytes) * prices.egressGib,
    requests: (monthlyRequests / 1_000_000) * prices.requestMillion,
  } : null;
  return {
    schemaVersion: CAPACITY_PLAN_SCHEMA_VERSION,
    workload: { ...workload },
    applicationBudgets: {
      reportRequestBytes: MAX_COMMUNITY_REPORT_REQUEST_BYTES,
      feedResponseBytes: MAX_COMMUNITY_FEED_RESPONSE_BYTES,
      feedEntries: MAX_COMMUNITY_FEED_ENTRIES,
      authoritativeSourceBytes: MAX_COMMUNITY_AUTHORITATIVE_SOURCE_BYTES,
      journalBytes: MAX_COMMUNITY_REPORT_JOURNAL_BYTES,
      destinationConcurrency: DESTINATION_ANALYSIS_CONCURRENCY,
      destinationQueue: MAX_DESTINATION_ANALYSIS_QUEUE,
      destinationCacheEntries: MAX_DESTINATION_CACHE_ENTRIES,
      backgroundIntervalMinutes: { minimum: MIN_BACKGROUND_INTERVAL_MINUTES, maximum: MAX_BACKGROUND_INTERVAL_MINUTES },
      backgroundConcurrentScans: 1,
      backgroundMessagesPerRun: 20,
    },
    projection: {
      dailyReports: round(dailyReports),
      monthlyRequests: round(monthlyRequests),
      monthlyIngestGib: round(gib(monthlyIngestBytes)),
      monthlyFeedEgressGib: round(gib(monthlyFeedEgressBytes)),
      projectedRetainedReportPayloadGib: round(gib(projectedRetainedReportPayloadBytes)),
      projectedAuthoritativeUsagePercent: round(usageRatio * 100),
      withinSeventyPercentStoragePlanningTarget: usageRatio <= 0.7,
      provisionedStorageGib: round(gib(provisionedStorageBytes)),
    },
    prices: prices ? { ...prices } : null,
    estimatedMonthlyCost: cost ? {
      compute: round(cost.compute),
      storage: round(cost.storage),
      egress: round(cost.egress),
      requests: round(cost.requests),
      total: round(cost.compute + cost.storage + cost.egress + cost.requests),
      currency: "operator_supplied_units",
    } : null,
    qualification: "planning_projection_not_a_throughput_or_availability_sla" as const,
  };
}
