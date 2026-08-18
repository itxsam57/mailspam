import express from "express";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createRuntimeWorkflowTraceRouter } from "../../server/src/api/runtimeWorkflowTraceRoutes.js";
import { createRuntimeTraceHttpMiddleware } from "../../server/src/diagnostics/runtimeTraceHttp.js";
import { createRuntimeWorkflowTraceRecorder } from "../../server/src/diagnostics/runtimeWorkflowTrace.js";

const servers: Server[] = [];
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

async function disabledTraceApi() {
  const app = express();
  app.use(express.json({ limit: "16kb", strict: true }));
  app.use("/api/dev/runtime-trace", createRuntimeWorkflowTraceRouter({ recorder: null }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe("EMA-5 fail-soft trace availability", () => {
  it("exposes a stable disabled config without accepting events when tracing is off", async () => {
    const baseUrl = await disabledTraceApi();
    const config = await fetch(`${baseUrl}/api/dev/runtime-trace/config`);
    expect(config.status).toBe(200);
    expect(await config.json()).toEqual({ enabled: false, localAuthoritative: true });

    const event = await fetch(`${baseUrl}/api/dev/runtime-trace/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    expect(event.status).toBe(404);
  });

  it("records one trusted backend terminal checkpoint from the server response boundary", () => {
    const directory = mkdtempSync(join(tmpdir(), "email-shield-runtime-http-terminal-"));
    directories.push(directory);
    const recorder = createRuntimeWorkflowTraceRecorder({
      dataDirectory: directory,
      environment: {
        EMAIL_SHIELD_RUNTIME_TRACE: "1",
        EMAIL_SHIELD_BUILD_COMMIT: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      },
      runId: "11111111-1111-4111-8111-111111111111",
    });
    const middleware = createRuntimeTraceHttpMiddleware({ recorder });
    const response = Object.assign(new EventEmitter(), { statusCode: 204 });
    let called = false;

    middleware({
      method: "POST",
      path: "/api/accounts/example/messages/report-scam",
      headers: { "x-email-shield-trace-id": "22222222-2222-4222-8222-222222222222" },
    }, response, () => {
      called = true;
      response.emit("finish");
    });

    expect(called).toBe(true);
    expect(recorder.readCurrent(10)).toEqual([
      expect.objectContaining({
        schemaVersion: 2,
        traceId: "22222222-2222-4222-8222-222222222222",
        workflowId: "message.report_scam",
        actionId: "message.report_scam",
        checkpointId: "message.report_scam.backend_completed",
        stage: "api_response",
        outcome: "success",
        httpStatus: 204,
      }),
    ]);
  });

  it("makes the browser probe trace availability and back off instead of repeatedly posting into disabled/rate-limited diagnostics", () => {
    const source = require("node:fs").readFileSync(join(import.meta.dirname, "../../web/local-security.js"), "utf8");
    expect(source).toContain("/api/dev/runtime-trace/config");
    expect(source).toContain("traceAvailability");
    expect(source).toContain("response.status === 429");
    expect(source).toContain("traceRetryAt");
  });
});
