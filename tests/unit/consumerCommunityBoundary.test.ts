import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

function webSource(name: string): string {
  return readFileSync(new URL(`../../web/${name}`, import.meta.url), "utf8");
}

describe("EMA-11 consumer Community and diagnostics boundary", () => {
  it("revokes Community in the authoritative router and retires direct #community navigation safely", () => {
    const uiRouter = webSource("ui-router.js");

    expect(uiRouter).not.toMatch(/const\s+ROUTES\s*=\s*Object\.freeze\(\[[^\]]*["']community["']/s);
    expect(uiRouter).toMatch(/RETIRED_ROUTES[\s\S]*community[\s\S]*home/i);
    expect(uiRouter).toMatch(/mainContent/);
    expect(uiRouter).toMatch(/operationsPanel/);
    expect(uiRouter).toMatch(/routeStack\(["']settings["']\)/);
    expect(uiRouter).toMatch(/data-route-target[\s\S]*community[\s\S]*(?:remove|removed)/i);
  });

  it("exposes operations diagnostics only inside entitled Settings diagnostics", () => {
    const developerControls = webSource("developer-controls.js");
    const operationsDashboard = webSource("operations-dashboard.js");

    expect(developerControls).toMatch(/operationsPanel/);
    expect(developerControls).toMatch(/operationsPanel[\s\S]*hidden\s*=\s*true|hidden\s*=\s*true[\s\S]*operationsPanel/i);
    expect(developerControls).toMatch(/developmentEntitlementsEnabled/);
    expect(developerControls).toMatch(/developer["']?\)\s*===\s*["']1["']|developer=1/);
    expect(developerControls).toMatch(/email-shield-developer-ui-enabled/);

    expect(operationsDashboard).not.toMatch(/communityVisible|#community|route\s*===\s*["']community["']/i);
    expect(operationsDashboard).toMatch(/emailShieldDeveloperEnabled/);
    expect(operationsDashboard).toMatch(/route[\s\S]*settings/i);
  });
});
