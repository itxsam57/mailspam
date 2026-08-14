import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repoRoot = resolve(process.cwd(), "..");
function source(path: string): string {
  return readFileSync(resolve(repoRoot, path), "utf8");
}

describe("consumer scanned-email presentation contract", () => {
  const renderer = source("web/consumer-scan-results.js");
  const selection = source("web/account-selection-state.js");
  const composition = source("server/src/api/dashboardScripts.ts");
  const gate = source("scripts/engineering/run-gate.mjs");

  it("loads synchronous account selection before the canonical scan owner and consumer renderer", () => {
    const selectionIndex = composition.indexOf('"/account-selection-state.js"');
    const scanIndex = composition.indexOf('"/scan-monitor.js"');
    const consumerIndex = composition.indexOf('"/consumer-scan-results.js"');
    expect(selectionIndex).toBeGreaterThanOrEqual(0);
    expect(scanIndex).toBeGreaterThan(selectionIndex);
    expect(consumerIndex).toBeGreaterThan(scanIndex);
  });

  it("reflects exactly one selected account synchronously before legacy async refresh/persistence", () => {
    expect(selection).toContain("window.selectAccount = function emailShieldSelectAccountState");
    expect(selection).toContain("reflectSelection(id);");
    expect(selection).toContain("return originalSelect.call(this, id, options);");
    expect(selection.indexOf("reflectSelection(id);")).toBeLessThan(selection.indexOf("return originalSelect.call(this, id, options);"));
    expect(selection).toContain("row.classList.toggle('active', active)");
    expect(selection).toContain("button.setAttribute('aria-pressed', String(active))");
    expect(selection).toContain("button.removeAttribute('aria-current')");
    expect(selection).not.toContain("setTimeout");
    expect(selection).not.toContain("requestAnimationFrame");
  });

  it("projects canonical diagnostic rows without opening a second scan stream", () => {
    expect(renderer).toContain('tr[data-message-row="true"]');
    expect(renderer).toContain("Scanned emails appear here as the scan progresses");
    expect(renderer).toContain("The newest 500 stay visible; the counters track the full scan");
    expect(renderer).toContain("new MutationObserver(render)");
    expect(renderer).toContain("observer.observe(tableBody, { childList: true })");
    expect(renderer).not.toContain("new EventSource");
    expect(renderer).not.toContain("/scan/quick");
    expect(renderer).not.toContain("/scan/full");
    expect(renderer).not.toContain("/scan/spam");
  });

  it("surfaces protected unsubscribe actions for safe newsletter rows without exposing destinations", () => {
    expect(renderer).toContain("row.dataset.unsubscribeAvailable !== 'true'");
    expect(renderer).toContain("button.dataset.action = 'unsubscribe'");
    expect(renderer).toContain("button.dataset.unsubscribeToken = token");
    expect(renderer).toContain("button.dataset.unsubscribeKey = actionKey");
    expect(renderer).toContain("['one_click_post', 'link_only', 'mailto']");
    expect(renderer).not.toContain("http://");
    expect(renderer).not.toContain("https://");
    expect(renderer).not.toContain("listUnsubscribe");
  });

  it("keeps executable consumer scan presentation in the blocking engineering gate", () => {
    expect(gate).toContain('npmStep("browser-scan"');
    expect(gate).toContain('"smoke:browser-scan"');
  });
});
