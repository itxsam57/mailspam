import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

const routes = read("server/src/api/consumerProtectionRoutes.ts");
const background = read("server/src/api/backgroundProtection.ts");
const healthWorker = read("server/src/workers/consumerHealthWorker.ts");
const metrics = read("server/src/api/localOperationalMetrics.ts");
const diagnosticsPath = join(root, "server/src/diagnostics/supportBundleDiagnostics.ts");

describe("EMA-20 privacy-safe Support Bundle diagnostic faithfulness", () => {
  it("declares persisted Activity and process-local operational metrics as different diagnostic scopes", () => {
    expect(metrics).toContain('scope: "current_process"');
    expect(routes).toContain("activityScope");
    expect(routes).toContain("operationalScope");
  });

  it("exports persisted scan-history aggregates so background Worker scans cannot disappear from support diagnostics", () => {
    expect(existsSync(diagnosticsPath)).toBe(true);
    expect(routes).toContain("scanHistoryDiagnostics");
    expect(routes).toContain("defaultScanStateRepository.list");
  });

  it("exports the existing background coordinator state instead of inventing a second scheduler", () => {
    expect(routes).toContain("backgroundProtection");
    expect(routes).toContain("backgroundProtection.status");
    expect(background).toContain("diagnosticSnapshot()");
    expect(background).toContain("schedulerLoopCount");
    expect(background).toContain("lastSchedulerTrigger");
  });

  it("reconciles Health cleanup workflow outcomes without pretending a no-change cleanup called moveToTrash", () => {
    expect(routes).toContain("cleanupWorkflowDiagnostics");
    expect(routes).toContain("BULK_CLEANUP_TO_TRASH");
    expect(routes).toContain("BULK_CLEANUP_NO_CHANGE");
    expect(healthWorker).toContain("if (ids.length) await adapter.moveToTrash");
  });

  it("integrates sanitized EMA-5 workflow diagnosis summaries without exporting raw trace records", () => {
    expect(existsSync(diagnosticsPath)).toBe(true);
    if (!existsSync(diagnosticsPath)) return;
    const diagnostics = read("server/src/diagnostics/supportBundleDiagnostics.ts");
    expect(diagnostics).toContain("diagnoseRuntimeWorkflow");
    expect(diagnostics).toContain("firstMissingCheckpoint");
    expect(diagnostics).toContain("lastSuccessfulCheckpoint");
    expect(diagnostics).not.toContain("rawTrace");
    expect(diagnostics).not.toContain("providerNativeId");
  });
});
