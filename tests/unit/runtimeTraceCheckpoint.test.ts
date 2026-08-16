import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  initializeRuntimeWorkflowTrace,
} from "../../server/src/diagnostics/runtimeWorkflowTrace.js";
import {
  recordRuntimeCheckpoint,
} from "../../server/src/diagnostics/runtimeTraceCheckpoint.js";

const temporaryDirectories: string[] = [];

function tempDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-runtime-checkpoint-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("runtime trace checkpoint contract", () => {
  it("records a stable workflow checkpoint through the single fail-soft helper", () => {
    const recorder = initializeRuntimeWorkflowTrace({
      dataDirectory: tempDirectory(),
      environment: {
        EMAIL_SHIELD_RUNTIME_TRACE: "1",
        EMAIL_SHIELD_BUILD_COMMIT: "af48ed7d2b70b9233aba9595d08aa337cc6b7fbf",
      },
      runId: "11111111-1111-4111-8111-111111111111",
      now: () => 1_700_000_000_000,
    });

    expect(recordRuntimeCheckpoint({
      traceId: "22222222-2222-4222-8222-222222222222",
      workflowId: "family.create",
      actionId: "family.create",
      checkpointId: "family.create.state_persisted",
      stage: "workflow",
      component: "family_service",
      outcome: "success",
    })).toBe(true);

    expect(recorder.readCurrent(10)).toEqual([
      expect.objectContaining({
        schemaVersion: 2,
        traceId: "22222222-2222-4222-8222-222222222222",
        workflowId: "family.create",
        actionId: "family.create",
        checkpointId: "family.create.state_persisted",
        buildId: "af48ed7d2b70b9233aba9595d08aa337cc6b7fbf",
        outcome: "success",
      }),
    ]);
  });

  it("never throws into product behavior when tracing is disabled or input is invalid", () => {
    initializeRuntimeWorkflowTrace({
      dataDirectory: tempDirectory(),
      environment: {},
      runId: "11111111-1111-4111-8111-111111111111",
    });

    expect(() => recordRuntimeCheckpoint({
      traceId: "not-a-trace-id",
      workflowId: "family.create",
      actionId: "family.create",
      checkpointId: "family.create.state_persisted",
      stage: "workflow",
      outcome: "success",
    })).not.toThrow();
    expect(recordRuntimeCheckpoint({
      traceId: "not-a-trace-id",
      workflowId: "family.create",
      actionId: "family.create",
      checkpointId: "family.create.state_persisted",
      stage: "workflow",
      outcome: "success",
    })).toBe(false);
  });
});
