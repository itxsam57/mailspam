import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(process.cwd(), "..");
const read = (path: string) => readFileSync(resolve(root, path), "utf8");

describe("owner QA entitlement launcher", () => {
  it("exposes one clearly named owner command without changing normal dev startup", () => {
    const pkg = JSON.parse(read("package.json")) as { scripts?: Record<string, string> };
    expect(pkg.scripts?.dev).toBe("node scripts/dev.mjs");
    expect(pkg.scripts?.["dev:owner-qa"]).toBe("node scripts/dev-owner-qa.mjs");
  });

  it("uses an explicit argv capability rather than a sticky environment variable", () => {
    const launcher = read("scripts/dev-owner-qa.mjs");
    const dev = read("scripts/dev.mjs");
    expect(launcher).toContain("--email-shield-owner-qa");
    expect(launcher).not.toContain("EMAIL_SHIELD_ENABLE_DEVELOPMENT_ENTITLEMENTS");
    expect(dev).toContain('const OWNER_QA_LAUNCH_ARG = "--email-shield-owner-qa"');
    expect(dev).toContain("dedicatedEntitlementLaunch");
    expect(dev).toContain("enforceDevelopmentEntitlementBoundary(process.env, dedicatedEntitlementLaunch)");
  });

  it("does not force a fixture mailbox or provider in the owner launcher", () => {
    const launcher = read("scripts/dev-owner-qa.mjs");
    expect(launcher).not.toContain("EMAIL_SHIELD_FIXTURE");
    expect(launcher).not.toContain("provider:");
    expect(launcher).not.toContain("mode:");
    expect(launcher).toContain("await import(\"./dev.mjs\")");
  });
});
