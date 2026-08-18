import { describe, expect, it } from "vitest";
import { createRuntimeWorkflowTraceRecorder } from "../../server/src/diagnostics/runtimeWorkflowTrace.js";
import {
  currentRuntimeTraceContext,
  recordCurrentRuntimeCheckpoint,
  runWithRuntimeTraceRequest,
} from "../../server/src/diagnostics/runtimeTraceRequestContext.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const workflow = {
  workflowId: "message.report_scam",
  actionId: "message.report_scam",
  provider: "gmail" as const,
};

function recorder() {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-trace-context-"));
  const value = createRuntimeWorkflowTraceRecorder({
    dataDirectory: directory,
    environment: {
      EMAIL_SHIELD_RUNTIME_TRACE: "1",
      EMAIL_SHIELD_BUILD_COMMIT: "188477f4d6a29ec534a30c2c3098fb71d9d2b247",
    },
  });
  return { directory, value };
}

describe("EMA-5 request trace correlation", () => {
  it("accepts only an opaque trace id from the browser and keeps server-resolved workflow identity authoritative", async () => {
    const traceId = "11111111-1111-4111-8111-111111111111";
    const result = await runWithRuntimeTraceRequest({
      "x-email-shield-trace-id": traceId,
      "x-email-shield-workflow-id": "spoofed.workflow",
      "x-email-shield-action-id": "spoofed.action",
      authorization: "must-not-be-read",
    }, workflow, async () => currentRuntimeTraceContext());

    expect(result).toEqual({
      traceId,
      workflowId: workflow.workflowId,
      actionId: workflow.actionId,
      provider: "gmail",
    });
    expect(currentRuntimeTraceContext()).toBeNull();
  });

  it("rejects malformed trace ids atomically", async () => {
    const result = await runWithRuntimeTraceRequest({
      "x-email-shield-trace-id": "not-a-uuid",
    }, workflow, async () => currentRuntimeTraceContext());
    expect(result).toBeNull();
    expect(currentRuntimeTraceContext()).toBeNull();
  });

  it("keeps concurrent request contexts isolated", async () => {
    const seen = await Promise.all([
      runWithRuntimeTraceRequest(
        { "x-email-shield-trace-id": "11111111-1111-4111-8111-111111111111" },
        workflow,
        async () => {
          await new Promise((resolve) => setTimeout(resolve, 10));
          return currentRuntimeTraceContext()?.traceId;
        },
      ),
      runWithRuntimeTraceRequest(
        { "x-email-shield-trace-id": "22222222-2222-4222-8222-222222222222" },
        { ...workflow, actionId: "message.mark_safe", workflowId: "message.mark_safe" },
        async () => {
          await Promise.resolve();
          return currentRuntimeTraceContext()?.traceId;
        },
      ),
    ]);
    expect(seen).toEqual([
      "11111111-1111-4111-8111-111111111111",
      "22222222-2222-4222-8222-222222222222",
    ]);
    expect(currentRuntimeTraceContext()).toBeNull();
  });

  it("records only safe checkpoint metadata under the bound server workflow", async () => {
    const { directory, value } = recorder();
    try {
      const recorded = await runWithRuntimeTraceRequest(
        { "x-email-shield-trace-id": "33333333-3333-4333-8333-333333333333" },
        workflow,
        async () => recordCurrentRuntimeCheckpoint(value, "backend_completed", {
          stage: "service",
          outcome: "success",
          component: "protection_actions",
        }),
      );
      expect(recorded).toBe(true);
      expect(value.readCurrent(10)[0]).toMatchObject({
        schemaVersion: 2,
        traceId: "33333333-3333-4333-8333-333333333333",
        workflowId: "message.report_scam",
        actionId: "message.report_scam",
        checkpointId: "message.report_scam.backend_completed",
      });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
