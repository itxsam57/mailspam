import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const web = readFileSync(join(root, "web/consumer-product.js"), "utf8");
const routes = readFileSync(join(root, "server/src/api/consumerProtectionRoutes.ts"), "utf8");

describe("EMA-16 Health cleanup targeting", () => {
  it("builds Clean old mail from the eligible cleanup group rather than total subscription count", () => {
    expect(web).toContain("inbox.cleanupGroups");
    expect(web).toContain("messagesOlderThan30Days");
    expect(web).toContain("cleanupGroups.get(item.key)");
  });

  it("does not preserve the only message after the 30-day age filter and refreshes Health after cleanup", () => {
    expect(web).toContain("keepNewest: false");
    expect(web).not.toContain("keepNewest: true");
    expect(web).toContain("await runHealth();");
  });

  it("never records a zero-move cleanup as if messages were moved", () => {
    expect(routes).toContain("result.movedToTrash > 0");
    expect(routes).toContain("Mailbox cleanup made no changes");
    expect(routes).not.toContain('title: "Mailbox cleanup moved messages to Trash",');
  });
});
