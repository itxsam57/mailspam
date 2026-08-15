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
    expect(source).toContain("requestSequence !== loadSequence || !selectionMatches(ownerSnapshot)");
    expect(source).toContain("cache: 'no-store'");
    expect(source).toContain("const mutationAccountId = loadedAccountId");
    expect(source).toContain("if (!selectionMatches(ownerSnapshot)) return");
    expect(source).toContain("loadedSelectionGeneration");
    expect(source).toContain("loadedPolicyMatchesSelection(ownerSnapshot)");
  });

  it("makes Personal Policy the one owned refresh boundary for Block and confirmed unsubscribe", () => {
    const policy = read("web/policy-management.js");
    const scan = read("web/scan-monitor.js");
    const unsubscribe = read("web/unsubscribe-monitor.js");
    expect(policy).toContain("Object.defineProperty(window, 'emailShieldRefreshPersonalPolicy'");
    expect(policy).toContain("value: () => loadPolicy(true)");
    expect(scan).toContain("const refresh = window.emailShieldRefreshPersonalPolicy");
    expect(scan).toContain("await refresh()");
    expect(scan).toContain("await policyChanged()");
    expect(unsubscribe).toContain("const refresh = window.emailShieldRefreshPersonalPolicy");
    expect(unsubscribe).toContain("await refresh()");
    expect(unsubscribe).toContain("await refreshPersonalPolicy()");
    expect(scan).not.toContain("document.getElementById('policyRefresh')?.click()");
    expect(unsubscribe).not.toContain("document.getElementById('policyRefresh')?.click()");
  });

  it("keeps live warning-card nodes stable while asynchronous actions are in flight", () => {
    const scan = read("web/scan-monitor.js");
    expect(scan).toContain("cards.insertAdjacentHTML('afterbegin', renderedCards)");
    expect(scan).not.toContain("progress.suspiciousCards.map(window.renderCard).join('') + cards.innerHTML");
    expect(scan).toContain("data-review-token");
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