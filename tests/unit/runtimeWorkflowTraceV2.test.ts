import { appendFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createRuntimeWorkflowTraceRecorder } from "../../server/src/diagnostics/runtimeWorkflowTrace.js";

const temporaryDirectories: string[] = [];

function tempDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-runtime-v2-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("runtime workflow trace schema v2", () => {
  it("writes v2 with workflow/build/checkpoint identity and rejects sensitive unknown fields", () => {
    const recorder = createRuntimeWorkflowTraceRecorder({
      dataDirectory: tempDirectory(),
      environment: {
        EMAIL_SHIELD_RUNTIME_TRACE: "1",
        EMAIL_SHIELD_BUILD_COMMIT: "188477f4d6a29ec534a30c2c3098fb71d9d2b247",
      },
      runId: "11111111-1111-4111-8111-111111111111",
      now: () => 1_700_000_000_000,
    });

    const base = {
      traceId: "22222222-2222-4222-8222-222222222222",
      workflowId: "mailbox.scan.full",
      actionId: "mailbox.scan.full",
      checkpointId: "scan.provider_page_read",
      stage: "provider",
      provider: "icloud",
      scanType: "full",
      component: "scan_worker",
      outcome: "success",
      pageSize: 2,
    } as const;

    expect(recorder.record(base)).toBe(true);
    expect(recorder.readCurrent(10)[0]).toMatchObject({
      schemaVersion: 2,
      workflowId: "mailbox.scan.full",
      checkpointId: "scan.provider_page_read",
      buildId: "188477f4d6a29ec534a30c2c3098fb71d9d2b247",
      pageSize: 2,
    });

    for (const forbidden of [
      { subject: "secret" },
      { email: "person@example.com" },
      { accountId: "account-secret" },
      { url: "https://secret.example/path?q=1" },
      { message: "raw provider exception" },
      { stack: "Error: secret" },
      { requestBody: { password: "secret" } },
    ]) {
      expect((recorder.record as (event: Record<string, unknown>) => boolean)({ ...base, ...forbidden })).toBe(false);
    }
  });

  it("keeps old v1 records readable without rewriting them as product state", () => {
    const recorder = createRuntimeWorkflowTraceRecorder({
      dataDirectory: tempDirectory(),
      environment: {
        EMAIL_SHIELD_RUNTIME_TRACE: "1",
        EMAIL_SHIELD_BUILD_COMMIT: "188477f4d6a29ec534a30c2c3098fb71d9d2b247",
      },
      runId: "11111111-1111-4111-8111-111111111111",
    });

    mkdirSync(dirname(recorder.filePath), { recursive: true });
    appendFileSync(recorder.filePath, `${JSON.stringify({
      schemaVersion: 1,
      timestamp: "2026-08-18T00:00:00.000Z",
      runId: "11111111-1111-4111-8111-111111111111",
      traceId: "22222222-2222-4222-8222-222222222222",
      stage: "workflow",
      actionId: "mailbox.scan.full",
      expectedWorkflow: "full_mailbox_audit",
      outcome: "success",
    })}\n`, { encoding: "utf8", mode: 0o600 });

    expect(recorder.readCurrent(10)).toEqual([
      expect.objectContaining({ schemaVersion: 1, actionId: "mailbox.scan.full" }),
    ]);
  });
});
