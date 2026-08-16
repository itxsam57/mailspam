import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const trace = readFileSync(join(root, "web/runtime-workflow-trace.js"), "utf8");
const diagnosis = readFileSync(join(root, "server/src/diagnostics/runtimeTraceDiagnosis.ts"), "utf8");

describe("sanitized browser runtime error tracing", () => {
  it("captures only same-origin code location plus fixed error codes", () => {
    expect(trace).toContain("uncaught_browser_error");
    expect(trace).toContain("unhandled_promise_rejection");
    expect(trace).toContain("errorLocationId");
    expect(trace).toContain("event.filename");
    expect(trace).toContain("event.lineno");
    expect(trace).not.toContain("event.message");
    expect(trace).not.toContain("event.error");
    expect(trace).not.toContain("event.reason");
    expect(trace).not.toContain(".stack");
  });

  it("lets diagnosis convert a safe error location into source path and line", () => {
    expect(diagnosis).toContain("errorLocationId");
    expect(diagnosis).toContain("browser_runtime");
    expect(diagnosis).toContain("runtime_error");
  });
});
