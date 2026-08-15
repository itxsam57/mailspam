import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("local browser provenance contract", () => {
  it("keeps ordinary navigation referrers private while explicitly proving protected same-origin API requests", () => {
    const server = readFileSync(new URL("../../server/src/api/localSecurity.ts", import.meta.url), "utf8");
    const browser = readFileSync(new URL("../../web/local-security.js", import.meta.url), "utf8");

    expect(server).toContain('res.setHeader("Referrer-Policy", "no-referrer")');
    expect(server).toContain("The protected read did not originate from this Email Shield dashboard.");
    expect(browser).toContain("referrer: `${window.location.origin}/`");
    expect(browser).toContain("referrerPolicy: 'same-origin'");
    expect(browser).toContain("...dashboardProvenance()");
    expect(browser).toContain("headers.set('X-Email-Shield-CSRF', csrfToken)");
  });
});
