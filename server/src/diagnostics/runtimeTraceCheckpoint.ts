import {
  runtimeWorkflowTrace,
  type RuntimeWorkflowTraceEventV2,
} from "./runtimeWorkflowTrace.js";

export type RuntimeCheckpointInput = RuntimeWorkflowTraceEventV2;

/**
 * Product owners emit evidence only through this helper. It never creates a
 * second workflow owner and never throws into protection behavior. The local
 * recorder remains the single validation/persistence authority.
 */
export function recordRuntimeCheckpoint(input: RuntimeCheckpointInput): boolean {
  try {
    return runtimeWorkflowTrace()?.record(input) ?? false;
  } catch {
    return false;
  }
}
