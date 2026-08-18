import { describe, expect, it } from "vitest";
import type { RuntimeWorkflowTraceRecordV2 } from "../../server/src/diagnostics/runtimeWorkflowTrace.js";
import { WORKFLOW_REGISTRY, runtimeWorkflowDefinition } from "../../server/src/diagnostics/workflowRegistry.js";
import { diagnoseRuntimeWorkflow } from "../../server/src/diagnostics/workflowDiagnosis.js";
import type { RuntimeTraceCheckpointManifest } from "../../server/src/diagnostics/checkpointManifest.js";

const buildId = "188477f4d6a29ec534a30c2c3098fb71d9d2b247";
const traceId = "22222222-2222-4222-8222-222222222222";
const runId = "11111111-1111-4111-8111-111111111111";

function record(
  workflowId: string,
  checkpointId: string,
  outcome: RuntimeWorkflowTraceRecordV2["outcome"] = "success",
): RuntimeWorkflowTraceRecordV2 {
  return {
    schemaVersion: 2,
    timestamp: "2026-08-18T00:00:00.000Z",
    runId,
    buildId,
    traceId,
    workflowId,
    actionId: workflowId,
    checkpointId,
    stage: checkpointId.endsWith("ui_confirmed") ? "ui_render" : "workflow",
    outcome,
  };
}

describe("EMA-5 deterministic workflow diagnosis", () => {
  it("registers the current critical consumer workflows with ordered checkpoints", () => {
    for (const workflowId of [
      "provider.connect.gmail",
      "provider.connect.icloud",
      "mailbox.scan.quick",
      "mailbox.scan.full",
      "mailbox.scan.spam",
      "message.report_scam",
      "message.mark_safe",
      "message.trust_sender",
      "message.unsubscribe",
      "message.analyze_links",
      "mailbox.health.run",
      "support.bundle.export",
      "account.profile.snapshot",
    ]) {
      const workflow = runtimeWorkflowDefinition(workflowId);
      expect(workflow, workflowId).not.toBeNull();
      expect(workflow!.requiredCheckpoints.length, workflowId).toBeGreaterThanOrEqual(2);
      expect(new Set(workflow!.requiredCheckpoints).size, workflowId).toBe(workflow!.requiredCheckpoints.length);
    }
    expect(Object.keys(WORKFLOW_REGISTRY).length).toBeGreaterThanOrEqual(13);
  });

  it("identifies the exact first missing checkpoint and its source owner", () => {
    const workflow = runtimeWorkflowDefinition("mailbox.scan.quick")!;
    const manifest: RuntimeTraceCheckpointManifest = {
      schemaVersion: 1,
      buildId,
      checkpoints: workflow.requiredCheckpoints.map((checkpointId, index) => ({
        checkpointId,
        workflowId: workflow.workflowId,
        component: index === workflow.requiredCheckpoints.length - 1 ? "runtime_workflow_trace_browser" : "scan_stream",
        sourcePath: index === workflow.requiredCheckpoints.length - 1 ? "web/runtime-workflow-trace.js" : "server/src/api/scanStream.ts",
        owner: index === workflow.requiredCheckpoints.length - 1 ? "uiConfirmation" : "scanLifecycle",
        line: 100 + index,
      })),
    };
    const completedBeforeUi = workflow.requiredCheckpoints.slice(0, -1).map((checkpointId) => record(workflow.workflowId, checkpointId));

    const diagnosis = diagnoseRuntimeWorkflow({ traceId, records: completedBeforeUi, workflow, manifest });
    expect(diagnosis).toMatchObject({
      terminalOutcome: "incomplete",
      lastSuccessfulCheckpoint: workflow.requiredCheckpoints.at(-2),
      firstMissingCheckpoint: workflow.requiredCheckpoints.at(-1),
      failedCheckpoint: null,
      suspectedOwner: {
        sourcePath: "web/runtime-workflow-trace.js",
        owner: "uiConfirmation",
        buildId,
      },
    });
  });

  it("pins an explicit failed checkpoint instead of blaming the next transition", () => {
    const workflow = runtimeWorkflowDefinition("message.report_scam")!;
    const manifest: RuntimeTraceCheckpointManifest = {
      schemaVersion: 1,
      buildId,
      checkpoints: workflow.requiredCheckpoints.map((checkpointId, index) => ({
        checkpointId,
        workflowId: workflow.workflowId,
        component: "protection_actions",
        sourcePath: "server/src/api/protectionActions.ts",
        owner: "reportScam",
        line: 200 + index,
      })),
    };
    const failedAt = workflow.requiredCheckpoints[1]!;
    const diagnosis = diagnoseRuntimeWorkflow({
      traceId,
      records: [
        record(workflow.workflowId, workflow.requiredCheckpoints[0]!),
        record(workflow.workflowId, failedAt, "failed"),
      ],
      workflow,
      manifest,
    });

    expect(diagnosis).toMatchObject({
      terminalOutcome: "failed",
      lastSuccessfulCheckpoint: workflow.requiredCheckpoints[0],
      failedCheckpoint: failedAt,
      firstMissingCheckpoint: null,
      suspectedOwner: {
        sourcePath: "server/src/api/protectionActions.ts",
        owner: "reportScam",
        buildId,
      },
    });
  });
});
