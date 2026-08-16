import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const trace = readFileSync(join(root, "web/runtime-workflow-trace.js"), "utf8");

describe("browser workflow trace v2 correlation", () => {
  it("puts workflowId on user action, API request, API response, and stream records", () => {
    expect(trace).toMatch(/function\s+begin\([^)]*workflowId/);
    expect(trace).toMatch(/stage:\s*['"]ui_action['"][\s\S]{0,500}workflowId/);
    expect(trace).toMatch(/stage:\s*['"]api_request['"][\s\S]{0,500}workflowId/);
    expect(trace).toMatch(/stage:\s*['"]api_response['"][\s\S]{0,500}workflowId/);
    expect(trace).toMatch(/function\s+streamTrace[\s\S]{0,900}workflowId/);
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
    expect(trace).toContain("function automaticRoot(");
    expect(trace).toContain("stage: 'system'");
    expect(trace).not.toMatch(/automaticRoot[\s\S]{0,1000}\.click\(/);
  });

  it("keeps scan correlation across the stream independently of the short click-to-request window", () => {
    expect(trace).toContain("const context = current()");
    expect(trace).toContain("const streamContext = () =>");
    expect(trace).toContain("scan-started");
    expect(trace).toContain("scan-complete");
  });
});
