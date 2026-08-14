import { afterEach, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { createLocalDesktopServer } from "../../server/src/api/localDesktopServer.js";
import { LocalSecurityManager } from "../../server/src/api/localSecurity.js";

interface BrowserContext {
  baseUrl: string;
  cookie: string;
  csrf: string;
  html: string;
}

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolveClose) => server.close(() => resolveClose()))));
});

async function startReleaseServer(): Promise<BrowserContext> {
  const app = createLocalDesktopServer({
    security: new LocalSecurityManager(),
    developmentEntitlementsEnabled: false,
  });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolveListen) => server.once("listening", () => resolveListen()));
  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;
  const home = await fetch(baseUrl);
  const html = await home.text();
  const cookie = home.headers.get("set-cookie")?.split(";", 1)[0] ?? "";
  const csrf = html.match(/<meta name="email-shield-csrf" content="([^"]+)"/)?.[1] ?? "";
  expect(home.status).toBe(200);
  expect(cookie).toMatch(/^email_shield_local_session=/);
  expect(csrf).not.toBe("");
  return { baseUrl, cookie, csrf, html };
}

function headers(context: BrowserContext): Record<string, string> {
  return {
    Cookie: context.cookie,
    Origin: context.baseUrl,
    Referer: `${context.baseUrl}/`,
    "X-Email-Shield-CSRF": context.csrf,
  };
}

async function nonce(context: BrowserContext): Promise<string> {
  const response = await fetch(`${context.baseUrl}/api/security/mutation-token`, {
    method: "POST",
    headers: headers(context),
  });
  const body = await response.json();
  expect(response.status).toBe(200);
  return String(body.nonce ?? "");
}

describe("production consumer release surface", () => {
  it("stamps the dashboard with an authoritative production-mode marker", async () => {
    const context = await startReleaseServer();
    expect(context.html).toContain('<meta name="email-shield-development-entitlements" content="false">');
  });

  it("does not expose the developer test-suite API in production mode", async () => {
    const context = await startReleaseServer();
    const response = await fetch(`${context.baseUrl}/api/dev/test-suite`, { headers: headers(context) });
    expect(response.status).toBe(404);
  });

  it("rejects fixture mailbox connections in production mode before fixture code can run", async () => {
    const context = await startReleaseServer();
    const response = await fetch(`${context.baseUrl}/api/accounts/connect`, {
      method: "POST",
      headers: {
        ...headers(context),
        "Content-Type": "application/json",
        "X-Email-Shield-Nonce": await nonce(context),
      },
      body: JSON.stringify({ provider: "gmail", mode: "fixture", label: "must-not-connect" }),
    });
    expect(response.status).toBe(404);
    expect(await response.json()).toMatchObject({ error: expect.stringMatching(/not available/i) });
  });

  it("keeps developer affordances behind the authoritative server flag and shell boundary", () => {
    const localSecurity = readFileSync(resolve(process.cwd(), "web/local-security.js"), "utf8");
    const consumer = readFileSync(resolve(process.cwd(), "web/consumer-product.js"), "utf8");
    expect(localSecurity).toContain("email-shield-development-entitlements");
    expect(localSecurity).toContain("emailShieldDevelopmentEntitlementsEnabled");
    expect(localSecurity).toContain("body.email-shield-shell > header { display: none !important; }");
    expect(consumer).toContain("window.emailShieldDevelopmentEntitlementsEnabled === true");
    expect(consumer).toContain("new URLSearchParams(location.search).get('developer') === '1'");
  });

  it("uses the canonical High Protection profile value in the browser", () => {
    const consumer = readFileSync(resolve(process.cwd(), "web/consumer-product.js"), "utf8");
    expect(consumer).toContain('data-consumer-sensitivity="high"');
    expect(consumer).not.toContain('data-consumer-sensitivity="high_protection"');
  });

  it("never tells consumers to configure OAuth client IDs themselves", () => {
    const gmail = readFileSync(resolve(process.cwd(), "web/gmail-oauth.js"), "utf8");
    const outlook = readFileSync(resolve(process.cwd(), "web/outlook-oauth.js"), "utf8");
    const copy = `${gmail}\n${outlook}`.toLowerCase();
    expect(copy).not.toContain("set the email shield desktop oauth client id");
    expect(copy).not.toContain("configure the desktop client id");
    expect(copy).not.toContain("set the email shield microsoft public-client id");
    expect(copy).not.toContain("configure the public desktop client id");
    expect(copy).not.toContain("development build");
  });
});
