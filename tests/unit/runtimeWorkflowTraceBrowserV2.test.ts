import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const trace = readFileSync(join(root, "web/runtime-workflow-trace.js"), "utf8");

function functionSection(name: string): string {
  const start = trace.indexOf(`function ${name}(`);
  expect(start, `function ${name} should exist`).toBeGreaterThanOrEqual(0);
  const next = trace.indexOf("\n  function ", start + 10);
  return trace.slice(start, next >= 0 ? next : trace.length);
}

describe("browser workflow trace v2 correlation", () => {
  it("puts workflowId on user action, API request, API response, and stream records", () => {
    const begin = functionSection("begin");
    const apiRequest = functionSection("apiRequest");
    const apiResponse = functionSection("apiResponse");
    const streamTrace = functionSection("streamTrace");

    expect(begin).toContain("workflowId: context.workflowId");
    expect(begin).toContain("stage: origin === 'automatic' ? 'system' : 'ui_action'");
    expect(apiRequest).toContain("workflowId: request.workflowId");
    expect(apiRequest).toContain("stage: 'api_request'");
    expect(apiResponse).toContain("workflowId: request.workflowId");
    expect(apiResponse).toContain("stage: 'api_response'");
    expect(streamTrace).toContain("workflowId: context.workflowId");
  });

  it("has one strict checkpoint API that cannot accept arbitrary object keys", () => {
    expect(trace).toContain("function checkpoint(");
    expect(trace).toContain("SAFE_CHECKPOINT_EXTRA_KEYS");
    expect(trace).toContain("checkpointId");
    expect(trace).toContain("workflowId");
    expect(trace).not.toContain("...safeExtra");
    expect(trace).not.toContain("...extra");
  });

  it("can create an automatic workflow root without synthesizing a user click", () => {
    const automaticRoot = functionSection("automaticRoot");
    const begin = functionSection("begin");
    expect(automaticRoot).toContain("return begin(actionId, workflowId, expectedWorkflow, provider, 'automatic')");
    expect(begin).toContain("stage: origin === 'automatic' ? 'system' : 'ui_action'");
    expect(automaticRoot).not.toContain(".click(");
  });

  it("keeps scan correlation across the stream independently of the click-to-request window", () => {
    expect(trace).toContain("const context = current()");
    expect(trace).toContain("const streamContext = () =>");
    expect(trace).toContain("scan-started");
    expect(trace).toContain("scan-complete");
  });
});
