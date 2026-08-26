import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("live scan refresh reattachment architecture", () => {
  it("loads reattachment before both scan monitor and workspace restore", () => {
    const source = read("server/src/api/dashboardScripts.ts");
    const reattach = source.indexOf('"/scan-live-reattach.js"');
    const monitor = source.indexOf('"/scan-monitor.js"');
    const restore = source.indexOf('"/workspace-restore.js"');
    expect(reattach).toBeGreaterThanOrEqual(0);
    expect(monitor).toBeGreaterThanOrEqual(0);
    expect(restore).toBeGreaterThanOrEqual(0);
    expect(reattach).toBeLessThan(monitor);
    expect(reattach).toBeLessThan(restore);
  });

  it("adopts a restored running scan without creating a second worker", () => {
    const source = read("web/scan-live-reattach.js");
    expect(source).toContain("email-shield-workspace-restored");
    expect(source).toContain("/api/accounts/workspace");
    expect(source).toContain("presentation.status === 'running'");
    expect(source).toContain("/scan/stop");
    expect(source).toContain("stopImmediatePropagation");
    expect(source).toContain("quickScanBtn");
    expect(source).toContain("fullScanBtn");
    expect(source).toContain("spamScanBtn");
    expect(source).not.toContain("emailShieldStartScan");
    expect(source).not.toContain("/scan/full");
    expect(source).not.toContain("/scan/quick");
  });

  it("keeps the protected workspace checkpoint advancing after the browser SSE detaches", () => {
    const source = read("server/src/api/scanStream.ts");
    const progressHandler = source.indexOf('message.type === "progress"');
    const detachedReturn = source.indexOf(
      "if (res.writableEnded || res.destroyed) return;",
      progressHandler,
    );
    const workspaceCheckpoint = source.indexOf(
      "sessionStore.rememberWorkspaceProgress",
      progressHandler,
    );

    expect(progressHandler).toBeGreaterThanOrEqual(0);
    expect(detachedReturn).toBeGreaterThan(progressHandler);
    expect(workspaceCheckpoint).toBeGreaterThan(progressHandler);
    expect(workspaceCheckpoint).toBeLessThan(detachedReturn);
  });

  it("rehydrates the selected mailbox only after the protected selection transaction settles", () => {
    const selection = read("web/account-selection-state.js");
    const reattach = read("web/scan-live-reattach.js");
    expect(selection).toContain("email-shield-account-selection-settled");
    expect(selection).toContain("async function persistSelection(snapshot, attempt)");
    expect(selection).toContain("body: JSON.stringify({ accountId: snapshot.id })");
    expect(selection).toContain("workspace?.selectedAccountId !== snapshot.id");
    expect(selection).toContain("originalSelect.call(this, id, { ...options, remember: false })");
    expect(selection).toContain("void settleWhenPersisted(snapshot)");
    expect(selection).not.toContain("Promise.resolve(result)");
    expect(reattach).toContain("email-shield-account-selection-settled");
    expect(reattach).toContain("await loadWorkspace()");
    expect(reattach).toContain("liveMonitorOwns(workspace)");
    expect(reattach).toContain("dispatchWorkspace(workspace)");
  });
});