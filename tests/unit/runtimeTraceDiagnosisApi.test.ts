import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const routes = readFileSync(join(root, "server/src/api/runtimeWorkflowTraceRoutes.ts"), "utf8");

describe("runtime trace diagnosis API architecture", () => {
  it("mounts manifest and diagnosis only inside the existing dev trace route owner", () => {
    expect(routes).toContain("/api/dev/runtime-trace/manifest");
    expect(routes).toContain("/api/dev/runtime-trace/diagnosis");
    expect(routes).toContain("loadRuntimeTraceManifest");
    expect(routes).toContain("diagnoseRuntimeTrace");
  });

  it("uses the same protected read boundary and never returns request content", () => {
    const manifestIndex = routes.indexOf("/api/dev/runtime-trace/manifest");
    const diagnosisIndex = routes.indexOf("/api/dev/runtime-trace/diagnosis");
    const manifestWindow = routes.slice(manifestIndex, manifestIndex + 2_000);
    const diagnosisWindow = routes.slice(diagnosisIndex, diagnosisIndex + 2_000);
    expect(manifestWindow).toMatch(/requireProtected(?:Read|Mutation)/);
    expect(diagnosisWindow).toMatch(/requireProtected(?:Read|Mutation)/);
    expect(manifestWindow).toContain("Cache-Control");
    expect(diagnosisWindow).toContain("Cache-Control");
    expect(routes).not.toContain("request.body");
    expect(routes).not.toContain("rawBody");
  });
});
