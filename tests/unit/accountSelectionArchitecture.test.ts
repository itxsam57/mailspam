import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("account selection authority architecture", () => {
  it("publishes one monotonic generation only after its exact workspace persistence transaction succeeds", () => {
    const source = read("web/account-selection-state.js");
    expect(source).toContain("let generation = 0");
    expect(source).toContain("if (changed) generation += 1");
    expect(source).toContain("email-shield-account-selection-changed");
    expect(source).toContain("email-shield-account-selection-settled");
    expect(source).toContain("email-shield-account-selection-persistence-failed");
    expect(source).toContain("new MutationObserver");
    expect(source).toContain("const activeId = accountsList.querySelector('.account-chip.active')?.dataset.id || null");
    expect(source).toContain("if (activeId !== selectedId) reflectSelection(activeId)");
    expect(source).toContain("async function persistSelection(snapshot, attempt)");
    expect(source).toContain("method: 'POST'");
    expect(source).toContain("body: JSON.stringify({ accountId: snapshot.id })");
    expect(source).toContain("workspace?.selectedAccountId !== snapshot.id");
    expect(source).toContain("if (!matches(snapshot) || attempt !== settleAttempt) return false");
    expect(source).toContain("publishSelectionSettled(snapshot)");
    expect(source).toContain("originalSelect.call(this, id, { ...options, remember: false })");
    expect(source).not.toContain("waitForPersistedSelection");
    expect(source).not.toContain("SETTLE_RETRY_MS");
    expect(source).not.toContain("SETTLE_TIMEOUT_MS");
    expect(source).toContain("ghost");
  });

  it("prevents delayed startup workspace restore from overwriting a newer tab-local mailbox selection", () => {
    const selection = read("web/account-selection-state.js");
    const restore = read("web/workspace-restore.js");
    expect(selection).toContain("capture,");
    expect(selection).toContain("generation: () => generation");
    expect(restore).toContain("const restoreSelectionSnapshot = window.emailShieldAccountSelection?.capture?.() ?? null");
    expect(restore).toContain("const currentSelectionSnapshot = window.emailShieldAccountSelection?.capture?.() ?? null");
    expect(restore).toContain("currentSelectionSnapshot.generation !== restoreSelectionSnapshot.generation");
    expect(restore).toContain("newer_tab_selection_preserved");
    expect(restore.indexOf("currentSelectionSnapshot.generation !== restoreSelectionSnapshot.generation")).toBeLessThan(
      restore.indexOf("select(workspace.selectedAccountId, { remember: false })"),
    );
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