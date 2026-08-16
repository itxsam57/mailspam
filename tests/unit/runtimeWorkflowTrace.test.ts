import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createRuntimeWorkflowTraceRecorder } from "../../server/src/diagnostics/runtimeWorkflowTrace.js";

const temporaryDirectories: string[] = [];

function tempDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-runtime-trace-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("runtime workflow trace recorder", () => {
  it("records only privacy-safe correlated workflow metadata", () => {
    const recorder = createRuntimeWorkflowTraceRecorder({
      dataDirectory: tempDirectory(),
      environment: { EMAIL_SHIELD_RUNTIME_TRACE: "1" },
      runId: "11111111-1111-4111-8111-111111111111",
      now: () => 1_700_000_000_000,
    });

    const accepted = recorder.record({
      traceId: "22222222-2222-4222-8222-222222222222",
      stage: "ui_action",
      actionId: "mailbox.scan.full",
      expectedWorkflow: "full_mailbox_audit",
      provider: "icloud",
      scanType: "full",
      component: "browser",
      step: "button_pressed",
      outcome: "started",
    });

    expect(accepted).toBe(true);
    expect(recorder.enabled).toBe(true);
    expect(recorder.runId).toBe("11111111-1111-4111-8111-111111111111");
    expect(recorder.readCurrent(10)).toEqual([
      {
        schemaVersion: 1,
        timestamp: "2023-11-14T22:13:20.000Z",
        runId: "11111111-1111-4111-8111-111111111111",
        traceId: "22222222-2222-4222-8222-222222222222",
        stage: "ui_action",
        actionId: "mailbox.scan.full",
        expectedWorkflow: "full_mailbox_audit",
        provider: "icloud",
        scanType: "full",
        component: "browser",
        step: "button_pressed",
        outcome: "started",
      },
    ]);
  });

  it("rejects unknown fields instead of ever persisting mailbox content or identity", () => {
    const recorder = createRuntimeWorkflowTraceRecorder({
      dataDirectory: tempDirectory(),
      environment: { EMAIL_SHIELD_RUNTIME_TRACE: "1" },
      runId: "11111111-1111-4111-8111-111111111111",
    });

    const record = recorder.record as (event: Record<string, unknown>) => boolean;
    expect(record({
      traceId: "22222222-2222-4222-8222-222222222222",
      stage: "ui_action",
      actionId: "mailbox.scan.full",
      expectedWorkflow: "full_mailbox_audit",
      outcome: "started",
      subject: "must never be recorded",
    })).toBe(false);
    expect(record({
      traceId: "22222222-2222-4222-8222-222222222222",
      stage: "api_request",
      actionId: "mailbox.scan.full",
      expectedWorkflow: "full_mailbox_audit",
      outcome: "started",
      accountId: "must-never-be-recorded",
    })).toBe(false);
    expect(record({
      traceId: "22222222-2222-4222-8222-222222222222",
      stage: "workflow",
      actionId: "mailbox.scan.full",
      expectedWorkflow: "full_mailbox_audit",
      outcome: "failed",
      error: "raw provider exception must never be recorded",
    })).toBe(false);
    expect(recorder.readCurrent(10)).toEqual([]);
  });

  it("is disabled outside explicit source/runtime tracing mode", () => {
    const directory = tempDirectory();
    const recorder = createRuntimeWorkflowTraceRecorder({
      dataDirectory: directory,
      environment: {},
      runId: "11111111-1111-4111-8111-111111111111",
    });
    expect(recorder.enabled).toBe(false);
    expect(recorder.record({
      traceId: "22222222-2222-4222-8222-222222222222",
      stage: "app",
      actionId: "application.start",
      expectedWorkflow: "desktop_runtime",
      component: "desktop_server",
      step: "started",
      outcome: "started",
    })).toBe(false);
    expect(() => readFileSync(recorder.filePath, "utf8")).toThrow();
  });

  it("bounds local storage and retains only recent rotated trace files", () => {
    const directory = tempDirectory();
    const recorder = createRuntimeWorkflowTraceRecorder({
      dataDirectory: directory,
      environment: { EMAIL_SHIELD_RUNTIME_TRACE: "1" },
      runId: "11111111-1111-4111-8111-111111111111",
      maxBytes: 900,
      maxFiles: 2,
    });

    for (let index = 0; index < 30; index += 1) {
      expect(recorder.record({
        traceId: "22222222-2222-4222-8222-222222222222",
        stage: "workflow",
        actionId: "mailbox.scan.full",
        expectedWorkflow: "full_mailbox_audit",
        provider: "icloud",
        scanType: "full",
        component: "scan_worker",
        step: `bounded_step_${index}`,
        outcome: "success",
        itemCount: index,
      })).toBe(true);
    }

    expect(recorder.traceFiles()).toHaveLength(2);
    expect(recorder.readCurrent(100).length).toBeGreaterThan(0);
  });
});
