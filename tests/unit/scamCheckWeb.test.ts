import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const scamCheck = readFileSync(new URL("../../web/scam-check.js", import.meta.url), "utf8");
const localSecurity = readFileSync(new URL("../../web/local-security.js", import.meta.url), "utf8");
const dashboardScripts = readFileSync(new URL("../../server/src/api/dashboardScripts.ts", import.meta.url), "utf8");

describe("Scam Check consumer web surface", () => {
  it("loads after the app shell and mounts into the consumer Scan surface", () => {
    expect(dashboardScripts.indexOf('"/app-shell.js"')).toBeGreaterThan(-1);
    expect(dashboardScripts.indexOf('"/scam-check.js"')).toBeGreaterThan(dashboardScripts.indexOf('"/app-shell.js"'));
    expect(scamCheck).toContain('.app-route[data-route="scan"] .shell-panel-stack');
    expect(scamCheck).toContain('Check something suspicious');
  });

  it("offers text, link and local file checks without a remote analysis endpoint", () => {
    expect(scamCheck).toContain("data-scam-check-mode=\"message\"");
    expect(scamCheck).toContain("data-scam-check-mode=\"url\"");
    expect(scamCheck).toContain("data-scam-check-mode=\"file\"");
    expect(scamCheck).toContain("/api/scam-check/v1/analyze");
    expect(scamCheck).toContain("/api/scam-check/v1/eml");
    expect(scamCheck).toContain("/api/scam-check/v1/image");
    expect(scamCheck).toContain("Nothing is sent to a remote AI service.");
    // A URL-shaped placeholder is legitimate UI copy. The privacy invariant is
    // that this module never fetches an absolute remote analysis endpoint.
    expect(scamCheck).not.toMatch(/fetch\(\s*['"`]https?:\/\//i);
    expect([...scamCheck.matchAll(/fetch\(\s*(['"`])([^'"`]+)\1/g)].map((match) => match[2]))
      .toEqual(expect.arrayContaining([
        "/api/scam-check/v1/analyze",
        "/api/scam-check/v1/eml",
        "/api/scam-check/v1/image",
      ]));
  });

  it("renders server evidence as text rather than injecting returned HTML", () => {
    expect(scamCheck).toContain("li.textContent = value");
    expect(scamCheck).toContain("summary.textContent");
    expect(scamCheck).not.toContain("data.explanation.summary}</");
    expect(scamCheck).not.toMatch(/innerHTML\s*=\s*data/);
  });

  it("adds CSRF/session protection but does not mint destructive-action nonces for analysis-only POSTs", () => {
    expect(localSecurity).toContain("path.startsWith('/api/scam-check')");
    expect(localSecurity).toContain("const analysisOnlyPath = (path) => path.startsWith('/api/scam-check/')");
    expect(localSecurity).toContain("!analysisOnlyPath(url.pathname)");
  });
});
