import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("EMA-5 owner-declared browser trace semantics", () => {
  it("lets feature-owner registrations override generic correlation without guessing Home Scan Now as a scan", () => {
    const tracer = read("web/runtime-workflow-trace.js");
    const registered = tracer.indexOf("registeredElements.get(button)");
    const fallback = tracer.indexOf("STATIC_CONTROLS[button.id]");
    expect(registered).toBeGreaterThanOrEqual(0);
    expect(fallback).toBeGreaterThan(registered);
    expect(tracer).not.toContain("homeScanNow: ['mailbox.scan.quick'");

    const shell = read("web/app-shell.js");
    expect(shell).toContain("registerControl('homeScanNow', 'navigation.scan'");
    expect(shell).toContain("registerControl('homeFamily', 'navigation.family'");
  });

  it("separates provider credential setup from actual provider connection and confirms Gmail only after OAuth completion", () => {
    const onboarding = read("web/consumer-provider-onboarding.js");
    const gmail = read("web/gmail-oauth.js");
    const registry = read("server/src/diagnostics/workflowRegistry.ts");

    expect(onboarding).toContain("registerControl");
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
      expect(registry).toContain(`\"${workflow}\"`);
    }
    expect(gmail).toContain("provider.connect.gmail.ui_confirmed");
  });

  it("gives automatic workspace restore and secondary legitimate learning their own roots and terminal checkpoints", () => {
    const restore = read("web/workspace-restore.js");
    const learning = read("web/protection-learning.js");
    const registry = read("server/src/diagnostics/workflowRegistry.ts");

    expect(restore).toContain("automaticRoot('system.workspace.restore', 'workspace.restore'");
    expect(restore).toContain("workspace.restore.started");
    expect(restore).toContain("workspace.restore.completed");
    expect(registry).toContain('automaticWorkflow("workspace.restore")');

    expect(learning).toContain("automaticRoot('system.learning.legitimate_feedback', 'learning.legitimate_feedback'");
    expect(learning).toContain("learning.legitimate_feedback.started");
    expect(learning).toContain("learning.legitimate_feedback.completed");
    expect(registry).toContain('automaticWorkflow("learning.legitimate_feedback")');
  });

  it("requires the separate consumer scan projection before a scan is visibly confirmed", () => {
    const projection = read("web/consumer-scan-results.js");
    const registry = read("server/src/diagnostics/workflowRegistry.ts");
    expect(projection).toContain("projection_rendered");
    expect(registry).toContain("`${workflowId}.projection_rendered`");
  });

  it("makes dynamic onboarding controls declare semantic ownership instead of relying on button text", () => {
    const onboarding = read("web/consumer-onboarding.js");
    const registry = read("server/src/diagnostics/workflowRegistry.ts");
    expect(onboarding).toContain("registerControl");
    expect(onboarding).toContain("onboarding.permissions.review");
    expect(onboarding).toContain("onboarding.family.skip");
    expect(onboarding).toContain("onboarding.complete");
    expect(registry).toContain('uiWorkflow("onboarding.permissions.review")');
    expect(registry).toContain('uiWorkflow("onboarding.family.skip")');
  });
});
