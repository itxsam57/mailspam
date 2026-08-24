import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("live scan refresh reattachment architecture", () => {
  it("loads a dedicated running-scan reattachment controller before workspace restore", () => {
    const source = read("server/src/api/dashboardScripts.ts");
    const reattach = source.indexOf('"/scan-live-reattach.js"');
    const restore = source.indexOf('"/workspace-restore.js"');
    expect(reattach).toBeGreaterThanOrEqual(0);
    expect(restore).toBeGreaterThanOrEqual(0);
    expect(reattach).toBeLessThan(restore);
  });

  it("adopts a restored running scan without creating a second worker", () => {
    const source = read("web/scan-live-reattach.js");
    expect(source).toContain("email-shield-workspace-restored");
    expect(source).toContain("/api/accounts/workspace");
    expect(source).toContain("email-shield-workspace-restored");
    expect(source).toContain("presentation.status === 'running'");
    expect(source).toContain("/scan/stop");
    expect(source).not.toContain("emailShieldStartScan");
    expect(source).not.toContain("/scan/full");
    expect(source).not.toContain("/scan/quick");
  });
});
