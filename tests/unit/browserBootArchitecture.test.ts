import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const read = (path: string): string => readFileSync(resolve(root, path), "utf8");

describe("browser boot architecture", () => {
  it("has one immutable owner for each published external browser global", () => {
    const webDir = resolve(root, "web");
    const owners = new Map<string, string[]>();
    for (const name of readdirSync(webDir).filter((entry) => entry.endsWith(".js"))) {
      const source = read(`web/${name}`);
      for (const match of source.matchAll(/Object\.defineProperty\(window,\s*['"]([^'"]+)['"]/g)) {
        const globalName = match[1]!;
        const files = owners.get(globalName) ?? [];
        files.push(name);
        owners.set(globalName, files);
      }
    }
    for (const [globalName, files] of owners) {
      expect(files, `${globalName} must have exactly one external browser-module owner`).toHaveLength(1);
    }
  });

  it("keeps shell navigation private and makes ui-router the public navigation owner", () => {
    const shell = read("web/app-shell.js");
    const router = read("web/ui-router.js");
    const composition = read("server/src/api/dashboardScripts.ts");
    expect(shell).not.toContain("Object.defineProperty(window, 'emailShieldNavigate'");
    expect(router).toContain("Object.defineProperty(window, 'emailShieldNavigate'");
    const shellIndex = composition.indexOf('"/app-shell.js"');
    const routerIndex = composition.indexOf('"/ui-router.js"');
    const consumerIndex = composition.indexOf('"/consumer-product.js"');
    expect(shellIndex).toBeGreaterThan(-1);
    expect(routerIndex).toBeGreaterThan(shellIndex);
    expect(consumerIndex).toBeGreaterThan(routerIndex);
  });

  it("installs the router observer only after its public navigation contract is published", () => {
    const router = read("web/ui-router.js");
    const publicNavigation = router.indexOf("Object.defineProperty(window, 'emailShieldNavigate'");
    const observer = router.indexOf("const observer = new MutationObserver");
    expect(publicNavigation).toBeGreaterThan(-1);
    expect(observer).toBeGreaterThan(publicNavigation);
  });

  it("retains the user-gesture-owned unsubscribe tab through asynchronous URL resolution", () => {
    const source = read("web/unsubscribe-monitor.js");
    expect(source).toContain("pendingWindow.location.replace(result.target)");
    expect(source).not.toContain("else window.open(result.target");
    expect(source).toContain("recordManualActivity(accountId, token, actionKey, method)");
    expect(source).toContain("not counted as a Confirmed unsubscribe");
  });

  it("has one scan/Stop/Resume owner and no legacy inline scan controller", () => {
    const html = read("web/index.html");
    const monitor = read("web/scan-monitor.js");
    const history = read("web/scan-history.js");
    expect(html).not.toContain("function startScan(");
    expect(html).not.toContain("function wireCardActions(");
    expect(html).not.toContain("currentEventSource");
    expect(html).not.toContain("new EventSource(`${API}/api/accounts/");
    expect(html).toContain("scan-monitor.js is the single scan/action");
    expect(monitor).toContain("Object.defineProperty(window, 'emailShieldStartScan'");
    expect(history).toContain("resumeScanButton.id = 'resumeScanBtn'");
    expect(history).toContain("stopScanButton?.insertAdjacentElement('afterend', resumeScanButton)");
    expect(history).toContain("const starter = window.emailShieldStartScan");
    expect(history).toContain("resumeScanId: scanId");
    expect(history).not.toContain("target.dataset.scanHistoryResume");
    expect(history).not.toContain("Resume newest");
  });

  it("binds block actions to opaque review tokens instead of browser-supplied policy values", () => {
    const review = read("web/review-actions.js");
    const monitor = read("web/scan-monitor.js");
    expect(review).toContain("senderBlock.dataset.reviewToken = action.token");
    expect(review).toContain("domainBlock.dataset.reviewToken = action.token");
    expect(review).not.toContain("dataset.action = 'unblock-sender'");
    expect(review).not.toContain("dataset.action = 'unblock-domain'");
    expect(monitor).toContain("const token = button.dataset.reviewToken");
    expect(monitor).toContain("body: JSON.stringify({ token })");
    expect(monitor).not.toContain("JSON.stringify({ address:");
    expect(monitor).not.toContain("JSON.stringify({ domain:");
    expect(monitor).toContain("attempt to move this current message to Trash");
  });

  it("keeps long scan result lists optional instead of forcing them open", () => {
    const monitor = read("web/scan-monitor.js");
    const consumer = read("web/consumer-scan-results.js");
    const safe = read("web/safe-audit.js");
    expect(monitor).toContain("diagnostics.open = false");
    expect(monitor).not.toContain("diagnostics.open = true");
    expect(consumer).toContain("document.createElement('details')");
    expect(consumer).toContain("feed.open = false");
    expect(safe).toContain("safeAudit.open = false");
    expect(safe).not.toContain("safeAudit.open = true");
    expect(monitor).toContain("progress.diagnosticSummaries");
  });

  it("preserves stopped scan presentation on Resume and requires server-final Stop confirmation", () => {
    const source = read("web/scan-monitor.js");
    const resumeGuard = source.indexOf("if (!resumeScanId) {");
    const clearCounters = source.indexOf("counters.innerHTML = ''", resumeGuard);
    const clearCards = source.indexOf("cards.innerHTML = ''", resumeGuard);
    const clearRows = source.indexOf("diagnosticRows = []", resumeGuard);
    expect(resumeGuard).toBeGreaterThan(-1);
    expect(clearCounters).toBeGreaterThan(resumeGuard);
    expect(clearCards).toBeGreaterThan(resumeGuard);
    expect(clearRows).toBeGreaterThan(resumeGuard);
    expect(source).toContain("value.resumed === true && value.counters");
    expect(source).toContain("result.active !== false");
    expect(source).toContain("result.historySaved === true && result.resumable === true");
    expect(source).toContain("serverFinal = result.active === false");
  });

  it("keeps all developer execution and fixture controls fail-closed in the normal consumer UI", () => {
    const controls = read("web/developer-controls.js");
    const composition = read("server/src/api/dashboardScripts.ts");
    const controlsIndex = composition.indexOf('"/developer-controls.js"');
    const shellIndex = composition.indexOf('"/app-shell.js"');
    expect(controlsIndex).toBeGreaterThan(-1);
    expect(controlsIndex).toBeLessThan(shellIndex);
    expect(controls).toContain("button.hidden = true");
    expect(controls).toContain("get('developer') === '1'");
    expect(controls).toContain("profile.developmentEntitlementsEnabled === true");
    expect(controls).toContain("new MutationObserver");
    expect(controls).toContain("Developer acceptance controls");
    expect(controls).toContain("data-email-shield-developer-control");
    expect(controls).toContain("detail.hidden = !developerUiEnabled");
    expect(controls).toContain("button.addEventListener('click', runDeveloperSuite, true)");
    expect(controls).toContain("event.stopImmediatePropagation()");
    expect(controls).toContain("results.textContent");
    expect(controls).not.toContain("results.innerHTML");
  });

  it("uses one visible desktop brand while preserving the compact mobile header", () => {
    const shell = read("web/app-shell.js");
    expect(shell).toContain("@media(min-width:901px){body.email-shield-shell>header{display:none}}");
    expect(shell).toContain("app-sidebar-brand");
  });
});