import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { initializeRuntimeWorkflowTrace } from "../../server/src/diagnostics/runtimeWorkflowTrace.js";
import { diagnoseRuntimeTrace, loadRuntimeTraceManifest } from "../../server/src/diagnostics/runtimeTraceDiagnosis.js";

const roots: string[] = [];
afterEach(() => {
  while (roots.length) rmSync(roots.pop()!, { recursive: true, force: true });
});

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "email-shield-diagnosis-"));
  roots.push(root);
  const buildId = "b".repeat(40);
  const recorder = initializeRuntimeWorkflowTrace({
    dataDirectory: root,
    environment: { EMAIL_SHIELD_RUNTIME_TRACE: "1", EMAIL_SHIELD_BUILD_COMMIT: buildId },
  });
  const manifestPath = join(root, "runtime-trace-manifest.json");
  return { root, buildId, recorder, manifestPath };
}

function writeManifest(path: string, buildId: string, entries: Array<Record<string, unknown>>) {
  mkdirSync(join(path, ".."), { recursive: true });
  writeFileSync(path, JSON.stringify({ buildId, generatedAt: new Date(0).toISOString(), entries }), "utf8");
}

describe("runtime trace diagnosis service", () => {
  it("rejects a stale-build manifest", () => {
    const { buildId, manifestPath } = fixture();
    writeManifest(manifestPath, "c".repeat(40), []);
    expect(loadRuntimeTraceManifest(buildId, manifestPath)).toBeNull();
  });

  it("identifies the first missing checkpoint and its exact source owner", () => {
    const { buildId, recorder, manifestPath } = fixture();
    const traceId = "33333333-3333-4333-8333-333333333333";
    recorder.record({
      traceId,
      workflowId: "message.trash",
      actionId: "message.trash",
      expectedWorkflow: "message.trash",
      checkpointId: "message.trash.requested",
      stage: "ui_action",
      outcome: "success",
    });
    recorder.record({
      traceId,
      workflowId: "message.trash",
      actionId: "message.trash",
      expectedWorkflow: "message.trash",
      checkpointId: "message.trash.backend_completed",
      stage: "service",
      outcome: "success",
    });
    writeManifest(manifestPath, buildId, [{
      checkpointId: "message.trash.ui_confirmed",
      workflowId: "message.trash",
      component: "scan_monitor",
      sourcePath: "web/scan-monitor.js",
      owner: "handleTrashAction",
      line: 412,
      buildId,
    }]);
    expect(diagnoseRuntimeTrace(traceId, manifestPath)).toMatchObject({
      traceId,
      workflowId: "message.trash",
      status: "incomplete",
      firstMissingCheckpointId: "message.trash.ui_confirmed",
      sourceOwner: {
        sourcePath: "web/scan-monitor.js",
        owner: "handleTrashAction",
        line: 412,
      },
    });
  });

  it("does not let HTTP/backend success replace visible UI confirmation", () => {
    const { buildId, recorder, manifestPath } = fixture();
    const traceId = "44444444-4444-4444-8444-444444444444";
    for (const checkpointId of ["message.report_scam.requested", "message.report_scam.backend_completed"]) {
      recorder.record({
        traceId,
        workflowId: "message.report_scam",
        actionId: "message.report_scam",
        expectedWorkflow: "message.report_scam",
        checkpointId,
        stage: checkpointId.endsWith("requested") ? "ui_action" : "service",
        outcome: "success",
      });
    }
    writeManifest(manifestPath, buildId, [{
      checkpointId: "message.report_scam.ui_confirmed",
      workflowId: "message.report_scam",
      component: "review_actions",
      sourcePath: "web/review-actions.js",
      owner: "review_action_handler",
      line: 300,
      buildId,
    }]);
    expect(diagnoseRuntimeTrace(traceId, manifestPath)?.status).toBe("incomplete");
  });
});
