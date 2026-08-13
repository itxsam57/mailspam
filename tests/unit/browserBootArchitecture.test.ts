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
  });

  it("exposes the existing protected resume owner beside Stop Scan", () => {
    const source = read("web/scan-history.js");
    expect(source).toContain("resumeScanButton.id = 'resumeScanBtn'");
    expect(source).toContain("stopScanButton?.insertAdjacentElement('afterend', resumeScanButton)");
    expect(source).toContain("const starter = window.emailShieldStartScan");
    expect(source).toContain("resumeScanId: scanId");
  });

  it("keeps destructive account action text readable on the danger background", () => {
    const source = read("web/account-lifecycle.js");
    expect(source).toContain("button.danger{border-color:var(--confirmed);background:var(--confirmed);color:#fff}");
  });

  it("keeps privacy-safe scanned messages visible while scan counters advance", () => {
    const source = read("web/scan-monitor.js");
    expect(source).toContain("Scanned messages (0)");
    expect(source).toContain("Scanned messages (${diagnosticRows.length})");
    expect(source).toContain("diagnostics.open = true");
    expect(source).not.toContain("diagnostics.open = false");
    expect(source).not.toContain("Local test view only");
    expect(source).toContain("progress.diagnosticSummaries");
  });

  it("uses one visible desktop brand while preserving the compact mobile header", () => {
    const shell = read("web/app-shell.js");
    expect(shell).toContain("@media(min-width:901px){body.email-shield-shell>header{display:none}}");
    expect(shell).toContain("app-sidebar-brand");
  });
});