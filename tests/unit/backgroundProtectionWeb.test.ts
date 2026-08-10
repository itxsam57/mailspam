import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(process.cwd(), "..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("background protection browser contract", () => {
  it("uses protected account-scoped APIs, safe text rendering and accessible status", () => {
    const html = read("web/index.html");
    const source = read("web/background-protection.js");
    const server = read("server/src/api/localDesktopServer.ts");

    expect(html).toContain('id="backgroundStatus"');
    expect(html).toContain('role="status" aria-live="polite"');
    expect(source).toContain("/background-protection");
    expect(source).toContain("status.textContent");
    expect(source).not.toContain("innerHTML");
    expect(source).not.toContain("localStorage");
    expect(source).not.toContain("sessionStorage");
    expect(server).toContain('app.get("/api/accounts/:id/background-protection"');
    expect(server).toContain('app.post("/api/accounts/:id/background-protection"');
    expect(server).toContain("backgroundProtection.remove(session.policyAccountKey)");
  });
});
