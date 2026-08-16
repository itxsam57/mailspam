import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const inventoryPath = join(root, ".engineering/runtime-trace-browser-modules.json");

function read(path: string): string {
  return readFileSync(join(root, path), "utf8");
}

function loadedDashboardScripts(): string[] {
  const source = read("server/src/api/dashboardScripts.ts");
  return [...source.matchAll(/"\/(.+?\.js)"/g)].map((match) => match[1]!);
}

describe("runtime trace dashboard module inventory", () => {
  it("classifies every loaded dashboard module exactly once", () => {
    expect(existsSync(inventoryPath), "dashboard trace inventory must exist").toBe(true);
    if (!existsSync(inventoryPath)) return;

    const parsed = JSON.parse(readFileSync(inventoryPath, "utf8")) as {
      schemaVersion: number;
      modules: Array<{ script: string; role: string; workflows: string[] }>;
    };
    expect(parsed.schemaVersion).toBe(1);
    const loaded = loadedDashboardScripts().sort();
    const classified = parsed.modules.map((entry) => entry.script).sort();
    expect(classified).toEqual(loaded);
    expect(new Set(classified).size).toBe(classified.length);

    const allowedRoles = new Set(["infrastructure", "feature_owner", "automatic", "projection", "secondary"]);
    for (const entry of parsed.modules) {
      expect(allowedRoles.has(entry.role), `${entry.script} has an invalid trace role`).toBe(true);
      if (entry.role !== "infrastructure") {
        expect(entry.workflows.length, `${entry.script} must declare at least one owned/observed workflow`).toBeGreaterThan(0);
      }
    }
  });

  it("does not confuse navigation, credential setup, provider connection, projections, or automatic restore", () => {
    expect(existsSync(inventoryPath), "dashboard trace inventory must exist").toBe(true);
    if (!existsSync(inventoryPath)) return;
    const parsed = JSON.parse(readFileSync(inventoryPath, "utf8")) as {
      modules: Array<{ script: string; role: string; workflows: string[] }>;
    };
    const byScript = new Map(parsed.modules.map((entry) => [entry.script, entry]));

    expect(byScript.get("app-shell.js")?.workflows).toContain("navigation.scan");
    expect(byScript.get("app-shell.js")?.workflows).not.toContain("mailbox.scan.quick");
    expect(byScript.get("consumer-provider-onboarding.js")?.workflows).toEqual(expect.arrayContaining([
      "provider.credentials.icloud",
      "provider.credentials.yahoo",
      "provider.credentials.imap",
      "provider.connect.gmail",
      "provider.connect.icloud",
      "provider.connect.yahoo",
      "provider.connect.imap",
    ]));
    expect(byScript.get("workspace-restore.js")).toMatchObject({ role: "automatic", workflows: ["workspace.restore"] });
    expect(byScript.get("gmail-oauth.js")?.workflows).toContain("provider.connect.gmail");
    expect(byScript.get("consumer-scan-results.js")?.role).toBe("projection");
    expect(byScript.get("protection-learning.js")?.role).toBe("secondary");
  });

  it("removes central button-id guesses for feature-owned controls", () => {
    const tracer = read("web/runtime-workflow-trace.js");
    expect(tracer).not.toContain("homeScanNow: ['mailbox.scan.quick'");
    expect(tracer).not.toContain("homeFamily: ['navigation.family'");
  });
});
