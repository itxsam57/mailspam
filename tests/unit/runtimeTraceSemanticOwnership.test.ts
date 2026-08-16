import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("runtime trace semantic ownership", () => {
  it("gives explicit owner registration precedence over legacy fallbacks and never guesses Home Scan Now as a Quick Scan", () => {
    const tracer = read("web/runtime-workflow-trace.js");
    const registeredLookup = tracer.indexOf("registeredElements.get(button)");
    const fallbackLookup = tracer.indexOf("STATIC_CONTROLS[button.id]");
    expect(registeredLookup).toBeGreaterThanOrEqual(0);
    expect(fallbackLookup).toBeGreaterThan(registeredLookup);
    expect(tracer).not.toContain("homeScanNow: ['mailbox.scan.quick'");
    expect(tracer).toContain("ui.unregistered_button");
  });

  it("makes the app shell declare Home navigation instead of pretending Scan Now executes a scan", () => {
    const shell = read("web/app-shell.js");
    expect(shell).toContain("registerControl('homeScanNow', 'navigation.scan'");
    expect(shell).toContain("registerControl('homeFamily', 'navigation.family'");
    expect(shell).not.toContain("home_quick_scan");
  });

  it("separates provider credential setup from the actual connection action", () => {
    const onboarding = read("web/consumer-provider-onboarding.js");
    for (const workflow of [
      "provider.credentials.icloud",
      "provider.credentials.yahoo",
      "provider.credentials.imap",
      "provider.connect.gmail",
      "provider.connect.icloud",
      "provider.connect.yahoo",
      "provider.connect.imap",
    ]) {
      expect(onboarding).toContain(workflow);
    }
    expect(onboarding).toContain("registerControl");
    expect(onboarding).toContain("provider.connect.gmail.ui_confirmed");
    expect(onboarding).toContain("provider.connect.icloud.ui_confirmed");
    expect(onboarding).toContain("provider.connect.yahoo.ui_confirmed");
    expect(onboarding).toContain("provider.connect.imap.ui_confirmed");
  });

  it("owns automatic workspace restore and secondary learning explicitly", () => {
    const restore = read("web/workspace-restore.js");
    const learning = read("web/protection-learning.js");
    expect(restore).toContain("automaticRoot('system.workspace.restore', 'workspace.restore'");
    expect(restore).toContain("workspace.restore.started");
    expect(restore).toContain("workspace.restore.completed");
    expect(learning).toContain("automaticRoot('system.learning.legitimate_feedback', 'learning.legitimate_feedback'");
    expect(learning).toContain("learning.legitimate_feedback.started");
    expect(learning).toContain("learning.legitimate_feedback.completed");
  });

  it("requires the separate consumer scan projection to participate before scan UI completion", () => {
    const projection = read("web/consumer-scan-results.js");
    const registry = read("server/src/diagnostics/workflowRegistry.ts");
    expect(projection).toContain("projection_rendered");
    expect(registry).toContain("`${workflowId}.projection_rendered`");
  });

  it("makes dynamic consumer onboarding controls declare semantic trace ownership", () => {
    const onboarding = read("web/consumer-onboarding.js");
    expect(onboarding).toContain("registerControl");
    expect(onboarding).toContain("onboarding.permissions.review");
    expect(onboarding).toContain("onboarding.family.skip");
    expect(onboarding).toContain("onboarding.complete");
  });
});
