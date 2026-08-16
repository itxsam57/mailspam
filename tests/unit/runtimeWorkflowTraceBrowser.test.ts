import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");

function source(path: string): string {
  return readFileSync(join(root, path), "utf8");
}

describe("browser runtime workflow tracing", () => {
  it("loads the semantic trace owner before browser feature controllers", () => {
    const dashboardScripts = source("server/src/api/dashboardScripts.ts");
    expect(dashboardScripts).toContain('"/runtime-workflow-trace.js"');
    expect(dashboardScripts.indexOf('"/runtime-workflow-trace.js"')).toBeLessThan(
      dashboardScripts.indexOf('"/scan-monitor.js"'),
    );
  });

  it("records stable control identity and expected workflow without DOM text or form values", () => {
    const trace = source("web/runtime-workflow-trace.js");
    for (const control of ["connectBtn", "quickScanBtn", "fullScanBtn", "spamScanBtn", "stopScanBtn", "backgroundToggle"]) {
      expect(trace).toContain(control);
    }
    expect(trace).toContain("mailbox.scan.full");
    expect(trace).toContain("full_mailbox_audit");
    expect(trace).toContain("data-action");
    expect(trace).toContain("data-route-target");
    expect(trace).not.toContain("innerText");
    expect(trace).not.toContain("textContent");
    expect(trace).not.toContain("input.value");
    expect(trace).not.toContain("credentials");
    expect(trace).not.toContain("subject");
  });

  it("correlates protected fetches and every same-origin scan EventSource centrally", () => {
    const localSecurity = source("web/local-security.js");
    const trace = source("web/runtime-workflow-trace.js");
    expect(localSecurity).toContain("X-Email-Shield-Trace-Id");
    expect(localSecurity).toContain("apiRequest");
    expect(localSecurity).toContain("apiResponse");
    expect(trace).toContain("withTraceQuery");
    expect(trace).toContain("class TracedEventSource");
  });
});
