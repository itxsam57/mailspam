import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  createRuntimeTraceHttpMiddleware,
  resolveRuntimeHttpWorkflow,
} from "../../server/src/diagnostics/runtimeTraceHttp.js";
import { currentRuntimeTraceContext } from "../../server/src/diagnostics/runtimeTraceRequestContext.js";

const root = join(import.meta.dirname, "../..");
const browserTrace = readFileSync(join(root, "web/runtime-workflow-trace.js"), "utf8");

describe("EMA-5 central runtime trace HTTP/browser wiring", () => {
  it("resolves protected routes to server-authoritative workflows without mailbox ids", () => {
    const cases = [
      ["GET", "/api/accounts/abc/scan/quick", "mailbox.scan.quick"],
      ["GET", "/api/accounts/abc/scan/full", "mailbox.scan.full"],
      ["GET", "/api/accounts/abc/scan/spam", "mailbox.scan.spam"],
      ["POST", "/api/accounts/abc/scan/stop", "mailbox.scan.stop"],
      ["POST", "/api/accounts/abc/messages/report-scam", "message.report_scam"],
      ["POST", "/api/accounts/abc/messages/mark-safe", "message.mark_safe"],
      ["POST", "/api/accounts/abc/messages/trust-sender", "message.trust_sender"],
      ["POST", "/api/accounts/abc/messages/unsubscribe", "message.unsubscribe"],
      ["POST", "/api/accounts/abc/messages/analyze-links", "message.analyze_links"],
      ["POST", "/api/consumer/v1/accounts/abc/health", "mailbox.health.run"],
      ["GET", "/api/consumer/v1/support-bundle", "support.bundle.export"],
      ["POST", "/api/accounts/workspace", "account.select"],
      ["DELETE", "/api/accounts/abc", "account.disconnect"],
    ] as const;

    for (const [method, path, workflowId] of cases) {
      const resolved = resolveRuntimeHttpWorkflow(method, path);
      expect(resolved, `${method} ${path}`).not.toBeNull();
      expect(resolved).toMatchObject({ workflowId, actionId: workflowId });
      expect(JSON.stringify(resolved)).not.toContain("abc");
    }
  });

  it("does not invent a workflow for unknown or ambiguous routes", () => {
    expect(resolveRuntimeHttpWorkflow("POST", "/api/accounts/connect")).toBeNull();
    expect(resolveRuntimeHttpWorkflow("POST", "/api/accounts/abc/messages/not-real")).toBeNull();
    expect(resolveRuntimeHttpWorkflow("GET", "/api/unknown/private/value")).toBeNull();
  });

  it("scopes the browser trace UUID to the server-resolved workflow for one request only", () => {
    const middleware = createRuntimeTraceHttpMiddleware();
    let inside = null;
    middleware({
      method: "POST",
      path: "/api/accounts/abc/messages/report-scam",
      headers: { "x-email-shield-trace-id": "22222222-2222-4222-8222-222222222222" },
    }, {}, () => {
      inside = currentRuntimeTraceContext();
    });

    expect(inside).toEqual({
      traceId: "22222222-2222-4222-8222-222222222222",
      workflowId: "message.report_scam",
      actionId: "message.report_scam",
    });
    expect(currentRuntimeTraceContext()).toBeNull();
  });

  it("runs unknown routes without creating diagnostic identity", () => {
    const middleware = createRuntimeTraceHttpMiddleware();
    let inside = "not-called";
    middleware({
      method: "POST",
      path: "/api/accounts/connect",
      headers: { "x-email-shield-trace-id": "22222222-2222-4222-8222-222222222222" },
    }, {}, () => {
      inside = currentRuntimeTraceContext();
    });
    expect(inside).toBeNull();
    expect(currentRuntimeTraceContext()).toBeNull();
  });

  it("emits schema-v2 browser workflow/checkpoint identity through one central owner", () => {
    expect(browserTrace).toContain("workflowId");
    expect(browserTrace).toContain("checkpointId");
    expect(browserTrace).toContain("function checkpoint(");
    expect(browserTrace).toContain("function registerControl(");
    expect(browserTrace).toContain("function automaticRoot(");
    expect(browserTrace).not.toContain("requestBody");
    expect(browserTrace).not.toContain("formValues");
  });
});
