import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function webSource(name: string): string {
  return readFileSync(new URL(`../../web/${name}`, import.meta.url), "utf8");
}

describe("EMA-11 consumer Community and diagnostics boundary", () => {
  it("removes Community from the authorized consumer route set and retires direct #community navigation safely", () => {
    const appShell = webSource("app-shell.js");
    const uiRouter = webSource("ui-router.js");

    expect(appShell).not.toMatch(/id:\s*["']community["']/);
    expect(uiRouter).not.toMatch(/const\s+ROUTES\s*=\s*\[[^\]]*["']community["']/s);
    expect(uiRouter).toMatch(/RETIRED_ROUTES[\s\S]*community[\s\S]*home/i);
    expect(uiRouter).toMatch(/mainContent/);
  });

  it("places operations diagnostics under Settings and gates them behind explicit developer entitlement", () => {
    const appShell = webSource("app-shell.js");
    const index = webSource("index.html");
    const developerControls = webSource("developer-controls.js");
    const operationsDashboard = webSource("operations-dashboard.js");

    expect(appShell).toMatch(/routeContainers\.get\(["']settings["']\)[\s\S]*operationsPanel/);
    expect(appShell).not.toMatch(/routeContainers\.get\(["']community["']\)[\s\S]*operationsPanel/);

    const operationsTag = index.match(/<section\b[^>]*\bid=["']operationsPanel["'][^>]*>/i)?.[0] ?? "";
    expect(operationsTag).toMatch(/\bhidden\b/i);

    expect(developerControls).toMatch(/operationsPanel/);
    expect(developerControls).toMatch(/developmentEntitlementsEnabled/);
    expect(developerControls).toMatch(/developer=1/);

    expect(operationsDashboard).not.toMatch(/communityVisible|#community|route\s*===\s*["']community["']/i);
    expect(operationsDashboard).toMatch(/settings/i);
  });
});
