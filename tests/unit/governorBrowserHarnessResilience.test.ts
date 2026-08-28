import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("Governor live-owner browser harness resilience", () => {
  it("retries only isolated DevTools startup/navigation failure from a fresh browser profile", () => {
    const wrapperPath = join(root, "scripts/engineering/smoke-governor-live-scan-owner-resilient.mjs");
    expect(existsSync(wrapperPath)).toBe(true);

    const rootPackage = JSON.parse(read("package.json"));
    const scanCommand = String(rootPackage.scripts?.["smoke:browser-scan"] ?? "");
    expect(scanCommand).toContain("smoke-governor-live-scan-owner-resilient.mjs");
    expect(scanCommand).not.toMatch(/node scripts\/engineering\/smoke-governor-live-scan-owner\.mjs(?:\s|$)/);

    const wrapper = read("scripts/engineering/smoke-governor-live-scan-owner-resilient.mjs");
    expect(wrapper).toContain("const MAX_BROWSER_ATTEMPTS = 2");
    expect(wrapper).toContain('"DevTools command timed out: Page.navigate"');
    expect(wrapper).toContain("retryableStartupFailure");
    expect(wrapper).toContain("spawnSync(process.execPath, [smokeScript]");
    expect(wrapper).toContain("Relaunching once from a fresh profile");
    expect(wrapper).not.toContain("Live progress was duplicated after A -> B -> A return");

    const smoke = read("scripts/engineering/smoke-governor-live-scan-owner.mjs");
    expect(smoke).toContain("maxRetries: 5");
    expect(smoke).toContain("retryDelay: 100");
  });
});
