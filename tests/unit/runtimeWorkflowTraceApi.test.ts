import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createRuntimeWorkflowTraceRecorder } from "../../server/src/diagnostics/runtimeWorkflowTrace.js";
import { createRuntimeWorkflowTraceRouter } from "../../server/src/api/runtimeWorkflowTraceRoutes.js";

const servers: Server[] = [];
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

async function start() {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-trace-api-"));
  directories.push(directory);
  const recorder = createRuntimeWorkflowTraceRecorder({
    dataDirectory: directory,
    environment: { EMAIL_SHIELD_RUNTIME_TRACE: "1" },
    runId: "11111111-1111-4111-8111-111111111111",
  });
  const app = express();
  app.use(express.json({ limit: "16kb", strict: true }));
  app.use("/api/dev/runtime-trace", createRuntimeWorkflowTraceRouter({ recorder }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return { recorder, baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

describe("runtime workflow trace API", () => {
  it("accepts only sanitized events and exposes the current bounded run", async () => {
    const { recorder, baseUrl } = await start();
    const accepted = await fetch(`${baseUrl}/api/dev/runtime-trace/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        traceId: "22222222-2222-4222-8222-222222222222",
        stage: "ui_action",
        actionId: "mailbox.scan.full",
        expectedWorkflow: "full_mailbox_audit",
        provider: "gmail",
        scanType: "full",
        component: "browser",
        step: "button_pressed",
        outcome: "started",
      }),
    });
    expect(accepted.status).toBe(202);
    expect(await accepted.json()).toEqual({ accepted: true });

    const current = await fetch(`${baseUrl}/api/dev/runtime-trace/current?limit=20`);
    expect(current.status).toBe(200);
    const body = await current.json();
    expect(body).toMatchObject({ enabled: true, runId: recorder.runId });
    expect(body.events).toHaveLength(1);
    expect(JSON.stringify(body)).not.toContain("accountId");
  });

  it("rejects an event carrying an unknown sensitive field", async () => {
    const { recorder, baseUrl } = await start();
    const rejected = await fetch(`${baseUrl}/api/dev/runtime-trace/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        traceId: "22222222-2222-4222-8222-222222222222",
        stage: "workflow",
        actionId: "mailbox.scan.full",
        expectedWorkflow: "full_mailbox_audit",
        outcome: "failed",
        accountId: "private-local-identity",
      }),
    });
    expect(rejected.status).toBe(400);
    expect(recorder.readCurrent(20)).toEqual([]);
  });
});
