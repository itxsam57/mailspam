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
});
