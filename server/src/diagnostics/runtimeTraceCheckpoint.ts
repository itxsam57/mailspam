import {
  runtimeWorkflowTrace,
  type RuntimeWorkflowTraceEventV2,
  type RuntimeWorkflowTraceRecorder,
} from "./runtimeWorkflowTrace.js";

export type RuntimeCheckpointInput = RuntimeWorkflowTraceEventV2;

/**
 * The single fail-soft write boundary for runtime workflow checkpoints.
 * Diagnostics must never become a product dependency: disabled tracing is a
 * no-op and recorder failures are contained here rather than escaping into the
 * protected workflow that emitted the evidence.
 */
export function recordRuntimeTraceCheckpoint(
  recorder: RuntimeWorkflowTraceRecorder | null,
  input: RuntimeCheckpointInput,
): boolean {
  if (!recorder?.enabled) return false;
  try {
    return recorder.record(input);
  } catch {
    return false;
  }
}

/** Product owners use the initialized local recorder through the same boundary. */
export function recordRuntimeCheckpoint(input: RuntimeCheckpointInput): boolean {
  return recordRuntimeTraceCheckpoint(runtimeWorkflowTrace(), input);
}
