import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

function source(path: string): string {
  return readFileSync(resolve(process.cwd(), path), "utf8");
}

describe("consumer scanned-email presentation contract", () => {
  const renderer = source("web/consumer-scan-results.js");
  const composition = source("server/src/api/dashboardScripts.ts");

  it("loads the all-message consumer renderer after the canonical scan monitor", () => {
    const scanIndex = composition.indexOf('"/scan-monitor.js"');
    const consumerIndex = composition.indexOf('"/consumer-scan-results.js"');
    expect(scanIndex).toBeGreaterThanOrEqual(0);
    expect(consumerIndex).toBeGreaterThan(scanIndex);
  });

  it("projects every canonical diagnostic row without opening a second scan stream", () => {
    expect(renderer).toContain('tr[data-message-row="true"]');
    expect(renderer).toContain("Every examined email appears here");
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
});
