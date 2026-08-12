import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dirname, "../..");
const web = join(root, "web");
const scripts = readFileSync(join(root, "server/src/api/dashboardScripts.ts"), "utf8");
const account = readFileSync(join(web, "account-plan.js"), "utf8");
const family = readFileSync(join(web, "family-shield.js"), "utf8");
const shell = readFileSync(join(web, "app-shell.js"), "utf8");
const protection = readFileSync(join(web, "protection-learning.js"), "utf8");

describe("account Family Shield and responsive application shell", () => {
  it("loads account, family and app-shell modules after existing feature modules", () => {
    expect(scripts).toContain('"/account-plan.js"');
    expect(scripts).toContain('"/family-shield.js"');
    expect(scripts).toContain('"/app-shell.js"');
    expect(scripts.indexOf('"/app-shell.js"')).toBeGreaterThan(scripts.indexOf('"/policy-management.js"'));
    expect(scripts.indexOf('"/app-shell.js"')).toBeGreaterThan(scripts.indexOf('"/scan-history.js"'));
  });

  it("provides desktop feature navigation and the five-item mobile bottom navigation", () => {
    for (const route of ["home", "scan", "protection", "family", "community", "history", "account", "settings"]) {
      expect(shell).toContain(`['${route}'`);
    }
    for (const item of ["Home", "Scan", "Family", "Activity", "More"]) expect(shell).toContain(item);
    expect(shell).toContain("@media(max-width:900px)");
  });

  it("does not persist account, family or mailbox data in browser storage", () => {
    for (const source of [account, family, shell, protection]) {
      expect(source).not.toMatch(/localStorage|sessionStorage|indexedDB/i);
    }
  });

  it("labels the local entitlement switch as development-only rather than paid subscription authority", () => {
    expect(account).toContain("Desktop acceptance plan preview");
    expect(account).toContain("does not represent a paid App Store, Google Play or web subscription");
    expect(account).toContain("developmentEntitlementsEnabled");
  });

  it("keeps Family Shield UI privacy-reduced and never serializes raw email fields", () => {
    expect(family).toContain("privacy-reduced campaign fingerprints only");
    expect(protection).toContain("shareWithFamily");
    for (const forbidden of ["rawBody", "bodyText", "htmlSignals", "providerNativeId", "messageId"]) {
      expect(family).not.toContain(forbidden);
      expect(account).not.toContain(forbidden);
    }
  });
});
