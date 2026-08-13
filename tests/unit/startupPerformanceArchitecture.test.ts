import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const read = (path: string): string => readFileSync(resolve(root, path), "utf8");

describe("desktop startup performance architecture", () => {
  it("starts development entry points directly instead of compiling the whole server first", () => {
    const pkg = JSON.parse(read("server/package.json")) as { scripts?: Record<string, string> };
    expect(pkg.scripts?.dev).toBe("tsx src/index.ts");
    expect(pkg.scripts?.["dev:community"]).toBe("tsx src/communityIndex.ts");
    expect(pkg.scripts?.["dev:account-service"]).toBe("tsx src/accountServiceIndex.ts");
    expect(pkg.scripts?.start).toBe("node dist/index.js");
  });

  it("initializes independent protected repositories in one awaited concurrent phase", () => {
    const source = read("server/src/index.ts");
    const vault = source.indexOf("const credentialVault = getRuntimeCredentialVault()");
    const concurrentPhase = source.indexOf("const initialized = await Promise.all([");
    const completion = source.indexOf("] as const);", concurrentPhase);
    const listen = source.indexOf("app.listen(");

    expect(vault).toBeGreaterThanOrEqual(0);
    expect(concurrentPhase).toBeGreaterThan(vault);
    expect(completion).toBeGreaterThan(concurrentPhase);
    expect(listen).toBeGreaterThan(completion);
    expect(source).toContain("initializeDefaultPersonalPolicyRepository({ credentialVault })");
    expect(source).toContain("initializeDefaultAccountPlatform({ credentialVault, dataDirectory })");
    expect(source).toContain("createDefaultInboundEventStateRepository({ credentialVault, dataDirectory })");
    expect(source).toContain("createDefaultLiveConnectionPersistence({ credentialVault, dataDirectory })");
  });

  it("defers dashboard modules so HTML parsing and first paint are not blocked by module downloads", () => {
    const source = read("server/src/api/dashboardScripts.ts");
    expect(source).toContain('<script defer src="${path}"></script>');
    expect(source).not.toContain('`<script src="${path}"></script>`');
  });

  it("keeps secondary dashboard hydration route-lazy", () => {
    const operations = read("web/operations-dashboard.js");
    const billing = read("web/billing-plan-ui.js");
    const guardian = read("web/family-guardian-preferences.js");

    expect(operations).toContain("event.detail?.route === 'community'");
    expect(operations).toContain("loadWhenVisible()");
    expect(billing).toContain("event.detail?.route === 'account'");
    expect(billing).not.toContain("setTimeout(mount, 350)");
    expect(guardian).toContain("event.detail?.route === 'family'");
    expect(guardian).not.toContain("setTimeout(() => { void load(); }, 600)");
  });
});
