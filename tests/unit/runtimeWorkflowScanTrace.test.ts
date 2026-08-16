import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const source = (path: string) => readFileSync(join(root, path), "utf8");

describe("runtime workflow trace propagation", () => {
  it("starts automatically for source live and fixture developer runs", () => {
    expect(source("scripts/dev.mjs")).toContain("EMAIL_SHIELD_RUNTIME_TRACE");
    expect(source("scripts/dev-fixtures.mjs")).toContain("EMAIL_SHIELD_RUNTIME_TRACE");
    expect(source("server/src/index.ts")).toContain("initializeRuntimeWorkflowTrace");
    expect(source("server/src/index.ts")).toContain("application.start");
  });

  it("mounts the developer trace API behind the protected local-session boundary", () => {
    const consumer = source("server/src/api/consumerDesktopServer.ts");
    const routes = source("server/src/api/runtimeWorkflowTraceRoutes.ts");
    expect(consumer).toContain("registerRuntimeWorkflowTraceRoutes");
    expect(routes).toContain("security.requireProtectedRead()");
    expect(routes).toContain("/api/dev/runtime-trace");
  });

  it("records the real scan provider, Worker batch boundary and terminal stream outcome", () => {
    const trace = source("web/runtime-workflow-trace.js");
    const stream = source("server/src/api/scanStream.ts");
    const worker = source("server/src/workers/scanWorker.ts");
    expect(trace).toContain("scan-started");
    expect(trace).toContain("scan-status");
    expect(trace).toContain("scan-complete");
    expect(trace).toContain("scan-error");
    expect(trace).toContain("bounded_batches");
    expect(stream).toContain("provider: session.provider");
    expect(worker).toContain("bounded batches of ${scanBatchPolicy.pageSize}");
  });
});
