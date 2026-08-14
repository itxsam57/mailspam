import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(process.cwd(), "..");
const read = (path: string) => readFileSync(resolve(root, path), "utf8");

describe("Personal Policy browser ownership", () => {
  it("prevents stale async policy reads from repainting after a newer mutation or account selection", () => {
    const source = read("web/policy-management.js");
    expect(source).toContain("let loadSequence = 0");
    expect(source).toContain("const requestSequence = ++loadSequence");
    expect(source).toContain("requestSequence !== loadSequence || selectedAccountId() !== accountId");
    expect(source).toContain("cache: 'no-store'");
    expect(source).toContain("const mutationAccountId = loadedAccountId");
    expect(source).toContain("selectedAccountId() !== mutationAccountId");
  });

  it("uses one semantic policy-refresh signal after Block and confirmed unsubscribe", () => {
    const scan = read("web/scan-monitor.js");
    const unsubscribe = read("web/unsubscribe-monitor.js");
    expect(scan).toContain("window.dispatchEvent(new CustomEvent('email-shield-policy-changed'))");
    expect(unsubscribe).toContain("window.dispatchEvent(new CustomEvent('email-shield-policy-changed'))");
    expect(scan).not.toContain("document.getElementById('policyRefresh')?.click()");
    expect(unsubscribe).not.toContain("document.getElementById('policyRefresh')?.click()");
  });

  it("keeps manual unsubscribe activity separate from confirmed encrypted policy", () => {
    const unsubscribe = read("web/unsubscribe-monitor.js");
    const policy = read("web/policy-management.js");
    expect(unsubscribe).toContain("Manual unsubscribe handoff recorded in Activity");
    expect(unsubscribe).toContain("not counted as a Confirmed unsubscribe");
    expect(policy).toContain("Confirmed unsubscribes");
    expect(policy).toContain("Opening an external unsubscribe page or email request is recorded in Activity instead");
  });
});
