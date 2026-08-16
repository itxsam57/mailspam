import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const webDir = join(root, "web");

function source(path: string): string {
  return readFileSync(join(root, path), "utf8");
}

function renderedButtons(): Array<{ id: string; tag: string }> {
  const declarations = [
    source("web/index.html"),
    ...readdirSync(webDir)
      .filter((name) => name.endsWith(".js"))
      .sort()
      .map((name) => source(`web/${name}`)),
  ].join("\n");
  const buttons: Array<{ id: string; tag: string }> = [];
  for (const match of declarations.matchAll(/<button\b[^>]*\bid=["']([^"']+)["'][^>]*>/gi)) {
    buttons.push({ id: match[1]!, tag: match[0] });
  }
  return buttons;
}

function genericTraceContract(tag: string): boolean {
  return /\bdata-route-target=/.test(tag)
    || /\bdata-mobile-route=/.test(tag)
    || /\bdata-action=/.test(tag)
    || /\bdata-select=/.test(tag)
    || /\bdata-consumer-provider=/.test(tag);
}

describe("full-product browser trace coverage", () => {
  it("gives every ordinary rendered button either a generic semantic contract or an explicit central registration", () => {
    const trace = source("web/runtime-workflow-trace.js");
    const unmapped = renderedButtons()
      .filter(({ tag }) => !genericTraceContract(tag))
      .map(({ id }) => id)
      .filter((id) => !new RegExp(`(?:^|[\\s,{])${id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*:`).test(trace));

    expect(unmapped).toEqual([]);
  });

  it("carries workflow identity and exposes only the central safe checkpoint/automatic-root APIs", () => {
    const trace = source("web/runtime-workflow-trace.js");
    expect(trace).toContain("workflowId");
    expect(trace).toContain("checkpoint:");
    expect(trace).toContain("automaticRoot:");
    expect(trace).toContain("registerControl:");
    expect(trace).not.toContain("session replay");
    expect(trace).not.toContain("requestBody");
    expect(trace).not.toContain("formValues");
  });

  it("keeps the trace owner first and leaves local-security as the single protected fetch wrapper", () => {
    const composition = source("server/src/api/dashboardScripts.ts");
    const traceIndex = composition.indexOf('"/runtime-workflow-trace.js"');
    const selectionIndex = composition.indexOf('"/account-selection-state.js"');
    expect(traceIndex).toBeGreaterThanOrEqual(0);
    expect(traceIndex).toBeLessThan(selectionIndex);

    const browserSources = readdirSync(webDir).filter((name) => name.endsWith(".js"));
    const fetchOwners = browserSources.filter((name) => /window\.fetch\s*=/.test(source(`web/${name}`)));
    expect(fetchOwners).toEqual(["local-security.js"]);
  });
});
