import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const boundaryPath = join(root, "web/runtime-workflow-error-boundary.js");
const diagnosis = readFileSync(join(root, "server/src/diagnostics/runtimeTraceDiagnosis.ts"), "utf8");
const composition = readFileSync(join(root, "server/src/api/dashboardScripts.ts"), "utf8");

describe("sanitized browser runtime error tracing", () => {
  it("loads a dedicated error boundary immediately after the core tracer", () => {
    expect(existsSync(boundaryPath), "browser runtime error boundary must exist").toBe(true);
    const tracer = composition.indexOf('"/runtime-workflow-trace.js"');
    const boundary = composition.indexOf('"/runtime-workflow-error-boundary.js"');
    expect(tracer).toBeGreaterThanOrEqual(0);
    expect(boundary).toBeGreaterThan(tracer);
    expect(composition.slice(tracer, boundary)).not.toContain('"/local-security.js"');
  });

  it("captures only same-origin code location plus fixed error codes", () => {
    expect(existsSync(boundaryPath), "browser runtime error boundary must exist").toBe(true);
    if (!existsSync(boundaryPath)) return;
    const boundary = readFileSync(boundaryPath, "utf8");
    expect(boundary).toContain("uncaught_browser_error");
    expect(boundary).toContain("unhandled_promise_rejection");
    expect(boundary).toContain("errorLocationId");
    expect(boundary).toContain("event.filename");
    expect(boundary).toContain("event.lineno");
    expect(boundary).toContain("event.colno");
    expect(boundary).not.toContain("event.message");
    expect(boundary).not.toContain("event.error");
    expect(boundary).not.toContain("event.reason");
    expect(boundary).not.toContain(".stack");
  });

  it("lets diagnosis convert a safe error location into source path and line", () => {
    expect(diagnosis).toContain("errorLocationId");
    expect(diagnosis).toContain("browser_runtime");
    expect(diagnosis).toContain("runtime_error");
  });
});
