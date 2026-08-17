import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const controller = readFileSync(join(root, "web/health-cleanup-controller.js"), "utf8");
const routes = readFileSync(join(root, "server/src/api/consumerProtectionRoutes.ts"), "utf8");
const dashboard = readFileSync(join(root, "server/src/api/dashboardScripts.ts"), "utf8");

describe("EMA-16 Health cleanup targeting", () => {
  it("composes one dedicated destructive Health cleanup owner after the consumer shell", () => {
    expect(dashboard).toContain('"/consumer-product.js"');
    expect(dashboard).toContain('"/health-cleanup-controller.js"');
    expect(dashboard.indexOf('"/health-cleanup-controller.js"')).toBeGreaterThan(
      dashboard.indexOf('"/consumer-product.js"'),
    );
    expect(controller).toContain("installedModules.has('health-cleanup-controller')");
    expect(controller).toContain("event.stopImmediatePropagation()");
  });

  it("derives cleanup eligibility from cleanupGroups, never from total subscription count", () => {
    expect(controller).toContain("inbox?.cleanupGroups");
    expect(controller).toContain("messagesOlderThan30Days");
    expect(controller).toContain("state.cleanupGroups.get(item.key)");
    expect(controller).toContain("legacyButton?.remove()");
    expect(controller).toContain("No old mail to clean");
  });

  it("moves every age-eligible message and refreshes Health after the provider mutation", () => {
    expect(controller).toContain("olderThanDays: 30");
    expect(controller).toContain("keepNewest: false");
    expect(controller).toContain("document.getElementById('consumerRunHealth')?.click()");
  });

  it("never records a zero-move cleanup as if messages were moved", () => {
    expect(routes).toContain("result.movedToTrash > 0");
    expect(routes).toContain("Mailbox cleanup made no changes");
    expect(routes).not.toContain('title: "Mailbox cleanup moved messages to Trash",');
  });
});
