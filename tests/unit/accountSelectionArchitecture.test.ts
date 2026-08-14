import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("account selection authority architecture", () => {
  it("publishes one monotonic generation and reconciles legacy account-list rebuilds", () => {
    const source = read("web/account-selection-state.js");
    expect(source).toContain("let generation = 0");
    expect(source).toContain("if (changed) generation += 1");
    expect(source).toContain("email-shield-account-selection-changed");
    expect(source).toContain("new MutationObserver");
    expect(source).toContain("const activeId = accountsList.querySelector('.account-chip.active')?.dataset.id || null");
    expect(source).toContain("if (activeId !== selectedId) reflectSelection(activeId)");
    expect(source).toContain("ghost account ID");
  });

  it("clears previously rendered scan content synchronously when mailbox selection changes", () => {
    const source = read("web/scan-monitor.js");
    expect(source).toContain("function clearScanPresentation()");
    expect(source).toContain("window.addEventListener('email-shield-account-selection-changed'");
    expect(source).toContain("counters.innerHTML = ''");
    expect(source).toContain("cards.innerHTML = ''");
    expect(source).toContain("diagnosticRows = []");
    expect(source).toContain("A scan is still running for another connected mailbox");
  });

  it("does not silently replace an active scan with a newly selected mailbox", () => {
    const source = read("web/scan-monitor.js");
    expect(source).toContain("if (source) {");
    expect(source).toContain("A scan for another mailbox is already active. Stop or finish that scan before starting the selected mailbox.");
    expect(source).not.toContain("source?.close();\n    source = null;\n    accountId = requestedAccountId");
  });
});