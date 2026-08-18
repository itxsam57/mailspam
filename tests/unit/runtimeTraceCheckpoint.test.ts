import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createRuntimeWorkflowTraceRecorder } from "../../server/src/diagnostics/runtimeWorkflowTrace.js";

const temporaryDirectories: string[] = [];
const modulePath = join(process.cwd(), "server", "src", "diagnostics", "runtimeTraceCheckpoint.ts");

function tempDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-runtime-checkpoint-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("runtime trace checkpoint helper", () => {
  it("exists as the single fail-soft checkpoint write boundary and records schema-v2 events", async () => {
    expect(existsSync(modulePath)).toBe(true);
    const module = await import(pathToFileURL(modulePath).href) as typeof import("../../server/src/diagnostics/runtimeTraceCheckpoint.js");
    const recorder = createRuntimeWorkflowTraceRecorder({
      dataDirectory: tempDirectory(),
      environment: {
        EMAIL_SHIELD_RUNTIME_TRACE: "1",
        EMAIL_SHIELD_BUILD_COMMIT: "188477f4d6a29ec534a30c2c3098fb71d9d2b247",
      },
      runId: "11111111-1111-4111-8111-111111111111",
      now: () => 1_700_000_000_000,
    });

    expect(module.recordRuntimeTraceCheckpoint(recorder, {
      traceId: "22222222-2222-4222-8222-222222222222",
      workflowId: "mailbox.scan.quick",
      actionId: "mailbox.scan.quick",
      checkpointId: "scan.request.accepted",
      stage: "request",
      component: "local_desktop_server",
      outcome: "success",
    })).toBe(true);

    expect(recorder.readCurrent(10)).toEqual([
      expect.objectContaining({
        schemaVersion: 2,
        workflowId: "mailbox.scan.quick",
        checkpointId: "scan.request.accepted",
      }),
    ]);
  });

  it("returns false without writing when disabled", async () => {
    expect(existsSync(modulePath)).toBe(true);
    const module = await import(pathToFileURL(modulePath).href) as typeof import("../../server/src/diagnostics/runtimeTraceCheckpoint.js");
    const recorder = createRuntimeWorkflowTraceRecorder({
      dataDirectory: tempDirectory(),
      environment: {},
      runId: "11111111-1111-4111-8111-111111111111",
    });
    const record = vi.spyOn(recorder, "record");

    expect(module.recordRuntimeTraceCheckpoint(recorder, {
      traceId: "22222222-2222-4222-8222-222222222222",
      workflowId: "mailbox.scan.quick",
      actionId: "mailbox.scan.quick",
      checkpointId: "scan.request.accepted",
      stage: "request",
      component: "local_desktop_server",
      outcome: "success",
    })).toBe(false);
    expect(record).not.toHaveBeenCalled();
  });

  it("never lets recorder failure break the product workflow", async () => {
    expect(existsSync(modulePath)).toBe(true);
    const module = await import(pathToFileURL(modulePath).href) as typeof import("../../server/src/diagnostics/runtimeTraceCheckpoint.js");
    const recorder = createRuntimeWorkflowTraceRecorder({
      dataDirectory: tempDirectory(),
      environment: {
        EMAIL_SHIELD_RUNTIME_TRACE: "1",
        EMAIL_SHIELD_BUILD_COMMIT: "188477f4d6a29ec534a30c2c3098fb71d9d2b247",
      },
      runId: "11111111-1111-4111-8111-111111111111",
    });
    vi.spyOn(recorder, "record").mockImplementation(() => { throw new Error("simulated recorder failure"); });

    expect(module.recordRuntimeTraceCheckpoint(recorder, {
      traceId: "22222222-2222-4222-8222-222222222222",
      workflowId: "mailbox.scan.quick",
      actionId: "mailbox.scan.quick",
      checkpointId: "scan.request.accepted",
      stage: "request",
      component: "local_desktop_server",
      outcome: "failure",
      reasonCode: "simulated_failure",
    })).toBe(false);
  });
});
