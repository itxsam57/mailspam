import { describe, expect, it } from "vitest";
import type { RuntimeWorkflowTraceRecordV2 } from "../../server/src/diagnostics/runtimeWorkflowTrace.js";
import type { RuntimeTraceCheckpointManifest } from "../../server/src/diagnostics/checkpointManifest.js";
import {
  diagnoseRuntimeWorkflow,
  type WorkflowDefinition,
} from "../../server/src/diagnostics/workflowDiagnosis.js";

const buildId = "c00b15d8701aae9eee8ccb428e5efe1789ffa2dd";
const traceId = "22222222-2222-4222-8222-222222222222";
const runId = "11111111-1111-4111-8111-111111111111";

const workflow: WorkflowDefinition = {
  workflowId: "family.create",
  actionIds: ["family.create"],
  requiredCheckpoints: [
    "family.create.request_validated",
    "family.create.state_persisted",
    "family.create.response_returned",
    "family.create.ui_confirmed",
  ],
  terminalCheckpoints: {
    success: ["family.create.ui_confirmed"],
    failed: [],
    rejected: [],
    cancelled: [],
    partial: [],
  },
};

const manifest: RuntimeTraceCheckpointManifest = {
  schemaVersion: 1,
  buildId,
  checkpoints: workflow.requiredCheckpoints.map((checkpointId, index) => ({
    checkpointId,
    workflowId: workflow.workflowId,
    component: index === 3 ? "family_shield_browser" : "family_service",
    sourcePath: index === 3 ? "web/family-shield.js" : "server/src/account/accountLifecycleService.ts",
    owner: index === 3 ? "renderFamilyCreated" : "createFamily",
    line: index === 3 ? 181 : 210 + index,
  })),
};

function record(checkpointId: string, outcome: RuntimeWorkflowTraceRecordV2["outcome"] = "success"): RuntimeWorkflowTraceRecordV2 {
  return {
    schemaVersion: 2,
    timestamp: "2026-08-16T05:00:00.000Z",
    runId,
    buildId,
    traceId,
    workflowId: workflow.workflowId,
    actionId: "family.create",
    stage: checkpointId.endsWith("ui_confirmed") ? "ui_render" : "workflow",
    checkpointId,
    outcome,
  };
}

describe("runtime workflow diagnosis", () => {
  it("requires the registered terminal checkpoint before declaring success", () => {
    const diagnosis = diagnoseRuntimeWorkflow({
      traceId,
      records: workflow.requiredCheckpoints.map((checkpointId) => record(checkpointId)),
      workflow,
      manifest,
    });

    expect(diagnosis).toMatchObject({
      workflowId: "family.create",
      terminalOutcome: "success",
      lastSuccessfulCheckpoint: "family.create.ui_confirmed",
      firstMissingCheckpoint: null,
      failedCheckpoint: null,
    });
  });

  it("reports backend success with missing UI confirmation as incomplete and points to the exact UI owner", () => {
    const diagnosis = diagnoseRuntimeWorkflow({
      traceId,
      records: [
        record("family.create.request_validated"),
        record("family.create.state_persisted"),
        record("family.create.response_returned"),
      ],
      workflow,
      manifest,
    });

    expect(diagnosis).toMatchObject({
      terminalOutcome: "incomplete",
      lastSuccessfulCheckpoint: "family.create.response_returned",
      firstMissingCheckpoint: "family.create.ui_confirmed",
      suspectedOwner: {
        sourcePath: "web/family-shield.js",
        owner: "renderFamilyCreated",
        line: 181,
        buildId,
      },
    });
  });

  it("reports an explicit failing checkpoint rather than blaming the next step", () => {
    const diagnosis = diagnoseRuntimeWorkflow({
      traceId,
      records: [
        record("family.create.request_validated"),
        record("family.create.state_persisted", "failed"),
      ],
      workflow,
      manifest,
    });

    expect(diagnosis).toMatchObject({
      terminalOutcome: "failed",
      lastSuccessfulCheckpoint: "family.create.request_validated",
      failedCheckpoint: "family.create.state_persisted",
      firstMissingCheckpoint: null,
      suspectedOwner: {
        sourcePath: "server/src/account/accountLifecycleService.ts",
        owner: "createFamily",
        line: 211,
        buildId,
      },
    });
  });

  it("does not infer success from a successful API response without workflow completion", () => {
    const response: RuntimeWorkflowTraceRecordV2 = {
      ...record("family.create.response_returned"),
      checkpointId: undefined,
      stage: "api_response",
      httpStatus: 200,
      outcome: "success",
    };

    const diagnosis = diagnoseRuntimeWorkflow({ traceId, records: [response], workflow, manifest });
    expect(diagnosis.terminalOutcome).toBe("incomplete");
    expect(diagnosis.firstMissingCheckpoint).toBe("family.create.request_validated");
  });
});
