import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("personal policy management browser boundary", () => {
  it("uses protected account APIs, DOM text rendering and no browser secret persistence", () => {
    const source = readFileSync(
      new URL("../../web/policy-management.js", import.meta.url),
      "utf8",
    );
    const desktop = readFileSync(
      new URL("../../server/src/api/localDesktopServer.ts", import.meta.url),
      "utf8",
    );
    const composition = readFileSync(
      new URL("../../server/src/api/dashboardScripts.ts", import.meta.url),
      "utf8",
    );

    expect(desktop).toContain('registerPolicyManagementRoutes(app)');
    expect(desktop).toContain('dashboardScriptTags(true)');
    expect(composition).toContain('"/policy-management.js"');
    expect(source).toContain('/personal-policy/export');
    expect(source).toContain('/bulk-revoke');
    expect(source).toContain('/clear-category');
    expect(source).toContain('/reset');
    expect(source).toContain('/import');
    expect(source).toContain("value.textContent = displayValue(item.category, item.value)");
    expect(source).toContain("listElement.replaceChildren()");
    expect(source).not.toContain("localStorage");
    expect(source).not.toContain("sessionStorage");
    expect(source).not.toContain("document.cookie");
    expect(source).not.toContain("refreshToken");
    expect(source).not.toContain("accessToken");
    expect(source).not.toContain("appPassword");
    expect(source).not.toContain("clientSecret");
    expect(source).not.toContain("accountKey");
  });
});
