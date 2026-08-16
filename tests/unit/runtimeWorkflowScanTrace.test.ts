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
    expect(consumer).toContain("registerRuntimeWorkflowTraceRoutes");
    expect(consumer).toContain("security.requireProtectedRead()");
    expect(consumer).toContain("/api/dev/runtime-trace");
  });

  it("propagates only an opaque trace id into the real scan stream and Worker", () => {
    const stream = source("server/src/api/scanStream.ts");
    const worker = source("server/src/workers/scanWorker.ts");
    expect(stream).toContain("trace_id");
    expect(stream).toContain("isRuntimeWorkflowTraceId");
    expect(stream).toContain("traceId,");
    expect(stream).toContain('message.type === "trace"');
    expect(worker).toContain("traceId?: string");
    expect(worker).toContain("batch_policy_resolved");
    expect(worker).toContain('type: "trace"');
    expect(worker).not.toContain("traceAccountId");
  });
});
