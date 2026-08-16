import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { initializeRuntimeWorkflowTrace } from "../../server/src/diagnostics/runtimeWorkflowTrace.js";
import {
  bindRuntimeTraceRequest,
  currentRuntimeTraceContext,
  recordCurrentRuntimeCheckpoint,
  startAutomaticRuntimeTrace,
} from "../../server/src/diagnostics/runtimeTraceRequestContext.js";

const directories: string[] = [];
afterEach(() => {
  while (directories.length) rmSync(directories.pop()!, { recursive: true, force: true });
});

function recorder() {
  const dataDirectory = mkdtempSync(join(tmpdir(), "email-shield-request-trace-"));
  directories.push(dataDirectory);
  return initializeRuntimeWorkflowTrace({
    dataDirectory,
    environment: {
      EMAIL_SHIELD_RUNTIME_TRACE: "1",
      EMAIL_SHIELD_BUILD_COMMIT: "a".repeat(40),
    },
  });
}

describe("runtime trace request context", () => {
  it("accepts only opaque safe correlation headers and never request content", () => {
    const traceId = "11111111-1111-4111-8111-111111111111";
    const bound = bindRuntimeTraceRequest({
      "x-email-shield-trace-id": traceId,
      "x-email-shield-workflow-id": "message.report_scam",
      "x-email-shield-action-id": "message.report_scam",
      "x-email-shield-provider": "gmail",
      "x-email-shield-request-body": "must-not-be-read",
    });
    expect(bound).toBe(true);
    expect(currentRuntimeTraceContext()).toEqual({
      traceId,
      workflowId: "message.report_scam",
      actionId: "message.report_scam",
      expectedWorkflow: "message.report_scam",
      provider: "gmail",
    });
  });

  it("rejects invalid context atomically instead of partially trusting headers", () => {
    expect(bindRuntimeTraceRequest({
      "x-email-shield-trace-id": "not-a-uuid",
      "x-email-shield-workflow-id": "message.report_scam",
      "x-email-shield-action-id": "message.report_scam",
    })).toBe(false);
    expect(currentRuntimeTraceContext()).toBeNull();
  });

  it("records a checkpoint under the bound request workflow without raw errors", () => {
    const sink = recorder();
    bindRuntimeTraceRequest({
      "x-email-shield-trace-id": "22222222-2222-4222-8222-222222222222",
      "x-email-shield-workflow-id": "message.report_scam",
      "x-email-shield-action-id": "message.report_scam",
    });
    expect(recordCurrentRuntimeCheckpoint("backend_completed", { stage: "service", outcome: "success", component: "report_scam" })).toBe(true);
    const [record] = sink.readCurrent();
    expect(record).toMatchObject({
      schemaVersion: 2,
      workflowId: "message.report_scam",
      checkpointId: "message.report_scam.backend_completed",
      stage: "service",
      outcome: "success",
    });
    expect(JSON.stringify(record)).not.toContain("stack");
    expect(JSON.stringify(record)).not.toContain("request-body");
  });

  it("creates independent automatic roots for background work", () => {
    const sink = recorder();
    const context = startAutomaticRuntimeTrace("protection.background.run", "background_scheduler");
    expect(context.workflowId).toBe("protection.background.run");
    expect(context.traceId).toMatch(/^[0-9a-f-]{36}$/i);
    expect(recordCurrentRuntimeCheckpoint("started", { stage: "system", outcome: "started", component: "background_scheduler" })).toBe(true);
    expect(sink.readCurrent().at(-1)).toMatchObject({
      traceId: context.traceId,
      workflowId: "protection.background.run",
      checkpointId: "protection.background.run.started",
    });
  });
});
