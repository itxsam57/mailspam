import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createRuntimeWorkflowTraceRecorder } from "../../server/src/diagnostics/runtimeWorkflowTrace.js";

const temporaryDirectories: string[] = [];

function tempDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-runtime-route-template-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("EMA-5 runtime trace route-template privacy boundary", () => {
  it("accepts only canonical privacy-safe route templates", () => {
    const recorder = createRuntimeWorkflowTraceRecorder({
      dataDirectory: tempDirectory(),
      environment: { EMAIL_SHIELD_RUNTIME_TRACE: "1" },
      runId: "11111111-1111-4111-8111-111111111111",
    });

    const base = {
      traceId: "22222222-2222-4222-8222-222222222222",
      workflowId: "mailbox.scan.quick",
      actionId: "mailbox.scan.quick",
      stage: "api_request",
      outcome: "started",
      component: "browser",
      step: "request_sent",
      httpMethod: "GET",
    } as const;

    expect(recorder.record({ ...base, routeTemplate: "/api/accounts/:accountId/scan/:type" })).toBe(true);

    for (const routeTemplate of [
      "/api/accounts/account-secret/scan/quick",
      "https://example.test/api/accounts/:accountId",
      "/api/accounts/:accountId?token=secret",
    ]) {
      expect(recorder.record({ ...base, routeTemplate })).toBe(false);
    }
  });
});
