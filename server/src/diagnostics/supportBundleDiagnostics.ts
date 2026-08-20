import type { PublicConsumerActivityRecord } from "../api/consumerStatePersistence.js";
import type { ScanHistoryRecord } from "../api/scanStatePersistence.js";
import type { RuntimeTraceCheckpointManifest } from "./checkpointManifest.js";
import { diagnoseRuntimeWorkflow } from "./workflowDiagnosis.js";
import { consumerRuntimeWorkflows } from "./workflowRegistry.js";
import {
  runtimeWorkflowTrace,
  type RuntimeWorkflowTraceRecordV2,
} from "./runtimeWorkflowTrace.js";

const SCAN_STATUSES = ["running", "interrupted", "completed", "failed", "stopped"] as const;
const SCAN_TYPES = ["quick", "full", "spam"] as const;
const COUNTER_KEYS = ["examined", "safe", "review", "highRisk", "confirmedThreat", "unknown", "skipped", "malformed"] as const;

export function scanHistoryDiagnostics(records: ScanHistoryRecord[]) {
  const statusCounts = Object.fromEntries(SCAN_STATUSES.map((status) => [status, 0])) as Record<typeof SCAN_STATUSES[number], number>;
  const typeCounts = Object.fromEntries(SCAN_TYPES.map((type) => [type, 0])) as Record<typeof SCAN_TYPES[number], number>;
  const counters = Object.fromEntries(COUNTER_KEYS.map((key) => [key, 0])) as Record<typeof COUNTER_KEYS[number], number>;
  let latestStartedAt: number | null = null;
  let latestCompletedAt: number | null = null;
  for (const record of records) {
    statusCounts[record.status] += 1;
    typeCounts[record.type] += 1;
    for (const key of COUNTER_KEYS) counters[key] += Math.max(0, Math.floor(record.counters[key]));
    latestStartedAt = latestStartedAt === null ? record.startedAt : Math.max(latestStartedAt, record.startedAt);
    if (record.completedAt !== null) {
      latestCompletedAt = latestCompletedAt === null ? record.completedAt : Math.max(latestCompletedAt, record.completedAt);
    }
  }
  return {
    scope: "persisted_local_scan_history" as const,
    retainedRecords: records.length,
    statusCounts,
    typeCounts,
    counters,
    latestStartedAt,
    latestCompletedAt,
  };
}

export function cleanupWorkflowDiagnostics(activity: PublicConsumerActivityRecord[]) {
  let movedToTrash = 0;
  let noChange = 0;
  let other = 0;
  let latestAt: number | null = null;
  for (const item of activity) {
    if (item.kind !== "cleanup") continue;
    latestAt = latestAt === null ? item.createdAt : Math.max(latestAt, item.createdAt);
    if (item.reasonCodes.includes("BULK_CLEANUP_TO_TRASH")) movedToTrash += 1;
    else if (item.reasonCodes.includes("BULK_CLEANUP_NO_CHANGE")) noChange += 1;
    else other += 1;
  }
  return {
    scope: "persisted_local_activity" as const,
    completedWithMutation: movedToTrash,
    completedWithoutMutation: noChange,
    otherCleanupRecords: other,
    latestAt,
  };
}

export function runtimeWorkflowDiagnosisSummaries(
  manifest: RuntimeTraceCheckpointManifest | null = null,
) {
  const recorder = runtimeWorkflowTrace();
  if (!recorder?.enabled) {
    return {
      available: false,
      scope: "current_diagnostic_run" as const,
      buildId: recorder?.buildId ?? null,
      ownerAttributionAvailable: false,
      summaries: [],
    };
  }

  const definitions = new Map(consumerRuntimeWorkflows().map((definition) => [definition.workflowId, definition]));
  const records = recorder.readCurrent(2_000).filter((record): record is RuntimeWorkflowTraceRecordV2 => record.schemaVersion === 2);
  const groups = new Map<string, { traceId: string; workflowId: string; buildId: string; records: RuntimeWorkflowTraceRecordV2[] }>();
  for (const record of records) {
    if (!definitions.has(record.workflowId)) continue;
    const key = record.traceId + ":" + record.workflowId;
    const group = groups.get(key) ?? {
      traceId: record.traceId,
      workflowId: record.workflowId,
      buildId: record.buildId,
      records: [],
    };
    group.records.push(record);
    groups.set(key, group);
  }

  const summaries = [...groups.values()].slice(-40).flatMap((group) => {
    const workflow = definitions.get(group.workflowId);
    if (!workflow) return [];
    const matchingManifest = manifest && manifest.buildId === group.buildId
      ? manifest
      : { schemaVersion: 1 as const, buildId: group.buildId, checkpoints: [] };
    const diagnosis = diagnoseRuntimeWorkflow({
      traceId: group.traceId,
      records: group.records,
      workflow,
      manifest: matchingManifest,
    });
    return [{
      workflowId: diagnosis.workflowId,
      terminalOutcome: diagnosis.terminalOutcome,
      lastSuccessfulCheckpoint: diagnosis.lastSuccessfulCheckpoint,
      firstMissingCheckpoint: diagnosis.firstMissingCheckpoint,
      failedCheckpoint: diagnosis.failedCheckpoint,
      suspectedOwner: diagnosis.suspectedOwner
        ? {
            component: diagnosis.suspectedOwner.component,
            sourcePath: diagnosis.suspectedOwner.sourcePath,
            owner: diagnosis.suspectedOwner.owner,
            line: diagnosis.suspectedOwner.line,
            buildId: diagnosis.suspectedOwner.buildId,
          }
        : null,
    }];
  });

  return {
    available: true,
    scope: "current_diagnostic_run" as const,
    buildId: recorder.buildId,
    ownerAttributionAvailable: Boolean(manifest && manifest.buildId === recorder.buildId),
    summaries,
  };
}
