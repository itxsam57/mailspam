import type { RuntimeWorkflowTraceRecordV2 } from "./runtimeWorkflowTrace.js";
import {
  checkpointOwner,
  type RuntimeTraceCheckpointManifest,
  type RuntimeTraceCheckpointOwner,
} from "./checkpointManifest.js";

export type WorkflowTerminalOutcome =
  | "success"
  | "failed"
  | "rejected"
  | "cancelled"
  | "partial"
  | "incomplete";

export interface WorkflowDefinition {
  workflowId: string;
  actionIds: string[];
  requiredCheckpoints: string[];
  terminalCheckpoints: {
    success: string[];
    failed: string[];
    rejected: string[];
    cancelled: string[];
    partial: string[];
  };
  internalOnly?: boolean;
}

export interface WorkflowDiagnosisOwner extends RuntimeTraceCheckpointOwner {
  buildId: string;
}

export interface WorkflowDiagnosis {
  traceId: string;
  workflowId: string;
  terminalOutcome: WorkflowTerminalOutcome;
  lastSuccessfulCheckpoint: string | null;
  failedCheckpoint: string | null;
  firstMissingCheckpoint: string | null;
  suspectedOwner: WorkflowDiagnosisOwner | null;
}

function sourceOwner(
  manifest: RuntimeTraceCheckpointManifest,
  checkpointId: string | null,
): WorkflowDiagnosisOwner | null {
  if (!checkpointId) return null;
  const owner = checkpointOwner(manifest, checkpointId);
  return owner ? { ...owner, buildId: manifest.buildId } : null;
}

function terminalFromOutcome(outcome: RuntimeWorkflowTraceRecordV2["outcome"]): WorkflowTerminalOutcome | null {
  switch (outcome) {
    case "failed": return "failed";
    case "rejected": return "rejected";
    case "cancelled": return "cancelled";
    case "partial": return "partial";
    case "incomplete": return "incomplete";
    default: return null;
  }
}

export function diagnoseRuntimeWorkflow(input: {
  traceId: string;
  records: RuntimeWorkflowTraceRecordV2[];
  workflow: WorkflowDefinition;
  manifest: RuntimeTraceCheckpointManifest;
}): WorkflowDiagnosis {
  const records = input.records.filter((record) => (
    record.schemaVersion === 2
    && record.traceId === input.traceId
    && record.workflowId === input.workflow.workflowId
    && record.buildId === input.manifest.buildId
  ));

  const successful = new Set<string>();
  let lastSuccessfulCheckpoint: string | null = null;
  let explicitTerminal: WorkflowTerminalOutcome | null = null;
  let failedCheckpoint: string | null = null;

  for (const record of records) {
    const checkpointId = record.checkpointId;
    if (checkpointId && record.outcome === "success") {
      successful.add(checkpointId);
      if (input.workflow.requiredCheckpoints.includes(checkpointId)) {
        lastSuccessfulCheckpoint = checkpointId;
      }
    }
    const terminal = terminalFromOutcome(record.outcome);
    if (terminal) {
      explicitTerminal = terminal;
      if (checkpointId) failedCheckpoint = checkpointId;
      break;
    }
  }

  if (explicitTerminal) {
    return {
      traceId: input.traceId,
      workflowId: input.workflow.workflowId,
      terminalOutcome: explicitTerminal,
      lastSuccessfulCheckpoint,
      failedCheckpoint,
      firstMissingCheckpoint: null,
      suspectedOwner: sourceOwner(input.manifest, failedCheckpoint),
    };
  }

  const successTerminals = new Set(input.workflow.terminalCheckpoints.success);
  const hasSuccessTerminal = [...successful].some((checkpointId) => successTerminals.has(checkpointId));
  const firstMissingCheckpoint = input.workflow.requiredCheckpoints.find((checkpointId) => !successful.has(checkpointId)) ?? null;

  if (hasSuccessTerminal && firstMissingCheckpoint === null) {
    return {
      traceId: input.traceId,
      workflowId: input.workflow.workflowId,
      terminalOutcome: "success",
      lastSuccessfulCheckpoint,
      failedCheckpoint: null,
      firstMissingCheckpoint: null,
      suspectedOwner: null,
    };
  }

  return {
    traceId: input.traceId,
    workflowId: input.workflow.workflowId,
    terminalOutcome: "incomplete",
    lastSuccessfulCheckpoint,
    failedCheckpoint: null,
    firstMissingCheckpoint,
    suspectedOwner: sourceOwner(input.manifest, firstMissingCheckpoint),
  };
}
