import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const serverRoot = join(root, "server/src");

function filesUnder(path: string): string[] {
  const output: string[] = [];
  for (const name of readdirSync(path)) {
    const full = join(path, name);
    if (statSync(full).isDirectory()) output.push(...filesUnder(full));
    else if (/\.(ts|js)$/.test(name)) output.push(full);
  }
  return output;
}

const serverSources = filesUnder(serverRoot).map((path) => ({
  path: relative(root, path).replaceAll("\\", "/"),
  source: readFileSync(path, "utf8"),
}));

function ownersOf(fragment: string): string[] {
  return serverSources.filter(({ source }) => source.includes(fragment)).map(({ path }) => path);
}

describe("server runtime trace coverage", () => {
  it("binds protected local requests into one AsyncLocalStorage trace context", () => {
    const context = readFileSync(join(serverRoot, "diagnostics/runtimeTraceRequestContext.ts"), "utf8");
    expect(context).toContain("AsyncLocalStorage");
    expect(context).toContain("bindRuntimeTraceRequest");
    expect(context).toContain("recordCurrentRuntimeCheckpoint");
    expect(context).not.toContain("request.body");
    expect(context).not.toContain("rawBody");

    const users = ownersOf("bindRuntimeTraceRequest(").filter((path) => !path.includes("diagnostics/runtimeTraceRequestContext"));
    expect(users.length).toBeGreaterThan(0);
  });

  it("sends workflow/action correlation from the protected browser fetch wrapper", () => {
    const source = readFileSync(join(root, "web/local-security.js"), "utf8");
    expect(source).toContain("X-Email-Shield-Trace-Id");
    expect(source).toContain("X-Email-Shield-Workflow-Id");
    expect(source).toContain("X-Email-Shield-Action-Id");
    expect(source).not.toContain("X-Email-Shield-Request-Body");
  });

  it("gives provider/session, scan, message mutation and automatic work server-side checkpoint owners", () => {
    const required = [
      "provider_authenticated",
      "connection_persisted",
      "request_validated",
      "provider_page_read",
      "checkpoint_persisted",
      "backend_completed",
      "startAutomaticRuntimeTrace(\"application.startup\"",
      "startAutomaticRuntimeTrace(\"provider.restore_sessions\"",
      "startAutomaticRuntimeTrace(\"protection.background.run\"",
      "startAutomaticRuntimeTrace(\"protection.realtime.run\"",
    ];
    const missing = required.filter((fragment) => ownersOf(fragment).length === 0);
    expect(missing).toEqual([]);
  });

  it("never uses raw exception text or stack traces as runtime checkpoint payload", () => {
    const traceOwners = serverSources.filter(({ source }) => source.includes("recordCurrentRuntimeCheckpoint(") || source.includes("recordRuntimeCheckpoint("));
    const violations: string[] = [];
    for (const { path, source } of traceOwners) {
      if (/record(?:Current)?RuntimeCheckpoint\([\s\S]{0,500}(?:error\.message|error\.stack|String\(error\))/.test(source)) violations.push(path);
    }
    expect(violations).toEqual([]);
  });
});
