import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

function read(path: string): string {
  return readFileSync(resolve(process.cwd(), path), "utf8");
}

describe("desktop startup performance architecture", () => {
  it("starts development entry points directly instead of compiling the whole server first", () => {
    const pkg = JSON.parse(read("package.json")) as { scripts?: Record<string, string> };
    expect(pkg.scripts?.dev).toBe("tsx src/index.ts");
    expect(pkg.scripts?.["dev:community"]).toBe("tsx src/communityIndex.ts");
    expect(pkg.scripts?.["dev:account-service"]).toBe("tsx src/accountServiceIndex.ts");
  });

  it("initializes independent protected repositories in one concurrent phase", () => {
    const source = read("src/index.ts");
    expect(source).toContain("const initialized = await Promise.all([");
    expect(source).toContain("initializeDefaultPersonalPolicyRepository({ credentialVault })");
    expect(source).toContain("initializeDefaultAccountPlatform({ credentialVault, dataDirectory })");
    expect(source).toContain("createDefaultInboundEventStateRepository({ credentialVault, dataDirectory })");
    expect(source).toContain("createDefaultLiveConnectionPersistence({ credentialVault, dataDirectory })");
  });

  it("defers dashboard modules so HTML parsing and first paint are not blocked by module downloads", () => {
    const source = read("src/api/dashboardScripts.ts");
    expect(source).toContain('<script defer src="${path}"></script>');
  });

  it("keeps secondary dashboard hydration route-lazy", () => {
    const operations = read(resolve("..", "web", "operations-dashboard.js"));
    const billing = read(resolve("..", "web", "billing-plan-ui.js"));
    const guardian = read(resolve("..", "web", "family-guardian-preferences.js"));

    expect(operations).toContain("event.detail?.route === 'community'");
    expect(operations).not.toContain("void load();\n})();");
    expect(billing).toContain("event.detail?.route === 'account'");
    expect(billing).not.toContain("setTimeout(mount, 350)");
    expect(guardian).toContain("event.detail?.route === 'family'");
    expect(guardian).not.toContain("setTimeout(() => { void load(); }, 600)");
  });
});
