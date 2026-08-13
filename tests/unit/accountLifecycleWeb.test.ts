import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const lifecycle = readFileSync(new URL("../../web/account-lifecycle.js", import.meta.url), "utf8");
const localSecurity = readFileSync(new URL("../../web/local-security.js", import.meta.url), "utf8");
const scripts = readFileSync(new URL("../../server/src/api/dashboardScripts.ts", import.meta.url), "utf8");

describe("account lifecycle browser contract", () => {
  it("loads after Account Plan and before the shell reorganizes the account route", () => {
    expect(scripts.indexOf('"/account-plan.js"')).toBeGreaterThan(-1);
    expect(scripts.indexOf('"/account-lifecycle.js"')).toBeGreaterThan(scripts.indexOf('"/account-plan.js"'));
    expect(scripts.indexOf('"/account-lifecycle.js"')).toBeLessThan(scripts.indexOf('"/app-shell.js"'));
  });

  it("protects every profile request with the shared browser CSRF/mutation wrapper", () => {
    expect(localSecurity).toContain("path.startsWith('/api/profile')");
    expect(localSecurity).toContain("headers.set('X-Email-Shield-CSRF', csrfToken)");
    expect(localSecurity).toContain("headers.set('X-Email-Shield-Nonce', await mutationNonce())");
  });

  it("uses only local lifecycle APIs and exact destructive/transfer confirmations", () => {
    for (const path of [
      "/api/profile/v1/recovery/rotate",
      "/api/profile/v1/devices/revoke-others",
      "/api/profile/v1/export",
      "/api/profile/v1/sign-out-everywhere",
      "/api/profile/v1/family/transfer",
      "/api/profile/v1/family",
      "/api/profile/v1/account",
    ]) expect(lifecycle).toContain(path);
    expect(lifecycle).toContain("typed !== 'TRANSFER FAMILY'");
    expect(lifecycle).toContain("typed !== 'DELETE FAMILY'");
    expect(lifecycle).toContain("typed !== 'DELETE ACCOUNT'");
    expect(lifecycle).toMatch(/store subscription is not transferred/i);
    expect(lifecycle).not.toMatch(/fetch\(\s*['"`]https?:\/\//i);
  });

  it("states that Email Shield profile deletion does not delete the provider mailbox", () => {
    expect(lifecycle).toMatch(/does NOT delete your Gmail\/Outlook\/iCloud\/Yahoo\/IMAP mailbox/i);
    expect(lifecycle).toMatch(/provider mailbox remains connected separately/i);
  });

  it("renders recovery and family-member values through textContent instead of HTML injection", () => {
    expect(lifecycle).toContain("value.textContent = code");
    expect(lifecycle).toContain("option.textContent = member.username");
    expect(lifecycle).not.toMatch(/innerHTML\s*=\s*.*recoveryCode/i);
    expect(lifecycle).not.toMatch(/innerHTML\s*=\s*.*member\.username/i);
  });
});
