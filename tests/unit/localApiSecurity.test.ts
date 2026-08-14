import { afterEach, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import { request as httpRequest, type Server } from "node:http";
import express, { type Express } from "express";
import { createLocalDesktopServer } from "../../server/src/api/localDesktopServer.js";
import { createServer } from "../../server/src/api/server.js";
import { LocalSecurityManager, redactSensitiveText } from "../../server/src/api/localSecurity.js";

interface BrowserContext {
  baseUrl: string;
  cookie: string;
  csrf: string;
}

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

async function listenBaseUrl(app: Express): Promise<string> {
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", () => resolve()));
  const port = (server.address() as AddressInfo).port;
  return `http://127.0.0.1:${port}`;
}

async function listen(app: Express): Promise<BrowserContext> {
  const baseUrl = await listenBaseUrl(app);
  const home = await fetch(baseUrl);
  const html = await home.text();
  const cookie = home.headers.get("set-cookie")?.split(";", 1)[0] ?? "";
  const csrf = html.match(/<meta name="email-shield-csrf" content="([^"]+)"/)?.[1] ?? "";
  expect(home.status).toBe(200);
  expect(cookie).toMatch(/^email_shield_local_session=/);
  expect(csrf.length).toBeGreaterThanOrEqual(32);
  return { baseUrl, cookie, csrf };
}

async function start(): Promise<BrowserContext> {
  return listen(createLocalDesktopServer({ security: new LocalSecurityManager() }));
}

async function startActionHarness(): Promise<BrowserContext> {
  const security = new LocalSecurityManager();
  const app = express();
  app.disable("x-powered-by");
  app.use(security.validateLoopbackRequest);
  app.use(security.securityHeaders);
  app.use(express.json({ limit: "4kb" }));
  app.get("/", (req, res) => {
    const context = security.openDashboard(req, res);
    res.type("html").send(`<meta name="email-shield-csrf" content="${context.csrfToken}">`);
  });
  app.post(
    "/api/security/mutation-token",
    security.requireProtectedRead(),
    security.requireSameOrigin(),
    (req, res) => security.issueMutationNonce(req, res),
  );
  app.post("/api/action", security.requireMutation(), (_req, res) => {
    res.json({ success: true });
  });
  return listen(app);
}

function headers(context: BrowserContext, overrides: Record<string, string> = {}): Record<string, string> {
  return {
    Cookie: context.cookie,
    Origin: context.baseUrl,
    Referer: `${context.baseUrl}/`,
    "X-Email-Shield-CSRF": context.csrf,
    ...overrides,
  };
}

async function rawStatus(baseUrl: string, requestHeaders: Record<string, string>): Promise<number> {
  const url = new URL(baseUrl);
  return new Promise<number>((resolve, reject) => {
    const request = httpRequest({
      hostname: url.hostname,
      port: Number(url.port),
      path: "/",
      method: "GET",
      headers: requestHeaders,
    }, (response) => {
      response.resume();
      response.on("end", () => resolve(response.statusCode ?? 0));
    });
    request.on("error", reject);
    request.end();
  });
}

async function nonce(context: BrowserContext): Promise<string> {
  const response = await fetch(`${context.baseUrl}/api/security/mutation-token`, {
    method: "POST",
    headers: headers(context),
  });
  const body = await response.json();
  expect(response.status).toBe(200);
  expect(body.nonce).toMatch(/^[A-Za-z0-9_-]{32,}$/);
  return body.nonce;
}

async function mutate(
  context: BrowserContext,
  path: string,
  body: unknown,
  method = "POST",
): Promise<Response> {
  return fetch(`${context.baseUrl}${path}`, {
    method,
    headers: headers(context, {
      "Content-Type": "application/json",
      "X-Email-Shield-Nonce": await nonce(context),
    }),
    body: method === "DELETE" ? undefined : JSON.stringify(body),
  });
}

describe("local desktop security boundary", () => {
  it("issues an HttpOnly session, hides it from HTML, and applies browser isolation headers", async () => {
    const context = await start();
    const response = await fetch(context.baseUrl);
    const html = await response.text();
    const setCookie = response.headers.get("set-cookie") ?? "";

    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("SameSite=Strict");
    expect(setCookie).toContain("Path=/");
    expect(html).toContain('/local-security.js');
    expect(html).not.toContain(context.cookie.split("=", 2)[1]);
    expect(response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(response.headers.get("x-frame-options")).toBe("DENY");
    expect(response.headers.get("cross-origin-opener-policy")).toBe("same-origin");
  });

  it("rejects account access without session, CSRF proof, and same-dashboard provenance", async () => {
    const context = await start();
    expect((await fetch(`${context.baseUrl}/api/accounts`)).status).toBe(401);
    expect((await fetch(`${context.baseUrl}/api/accounts`, {
      headers: { Cookie: context.cookie },
    })).status).toBe(403);
    expect((await fetch(`${context.baseUrl}/api/accounts`, {
      headers: headers(context, {
        Origin: "https://attacker.example",
        Referer: "https://attacker.example/",
        "Sec-Fetch-Site": "cross-site",
      }),
    })).status).toBe(403);
    expect((await fetch(`${context.baseUrl}/api/accounts`, {
      headers: headers(context),
    })).status).toBe(200);
  });

  it("protects the aggregate-only operations snapshot and emits no mailbox/content fields", async () => {
    const context = await start();
    expect((await fetch(`${context.baseUrl}/api/operations/v1/snapshot`)).status).toBe(401);
    const response = await fetch(`${context.baseUrl}/api/operations/v1/snapshot`, { headers: headers(context) });
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = await response.json();
    expect(body).toMatchObject({
      schemaVersion: 1,
      privacy: "aggregate_only_no_mailbox_identity_or_content",
      local: { schemaVersion: 1 },
      providerContracts: expect.arrayContaining([expect.objectContaining({ provider: "gmail" })]),
    });
    const serialized = JSON.stringify(body);
    for (const forbidden of ["subject", "fromAddress", "messageId", "accountId", "providerNativeId", "exception", "token", "body"]) {
      expect(serialized).not.toContain(`\"${forbidden}\"`);
    }
  });

  it("rejects DNS rebinding, forwarded requests, and another local origin", async () => {
    const context = await start();
    expect(await rawStatus(context.baseUrl, { Host: "attacker.example" })).toBe(421);
    expect((await fetch(context.baseUrl, { headers: { "X-Forwarded-Host": "attacker.example" } })).status).toBe(421);
    expect((await fetch(`${context.baseUrl}/api/security/mutation-token`, {
      method: "POST",
      headers: headers(context, { Origin: "http://127.0.0.1:65531" }),
    })).status).toBe(403);
  });

  it("requires a single-use mutation nonce independently of mailbox fixture availability", async () => {
    const context = await startActionHarness();
    const mutationNonce = await nonce(context);
    const request = () => fetch(`${context.baseUrl}/api/action`, {
      method: "POST",
      headers: headers(context, {
        "Content-Type": "application/json",
        "X-Email-Shield-Nonce": mutationNonce,
      }),
      body: "{}",
    });

    expect((await request()).status).toBe(200);
    expect((await request()).status).toBe(409);
    expect((await fetch(`${context.baseUrl}/api/action`, {
      method: "POST",
      headers: headers(context, { "Content-Type": "application/json" }),
      body: "{}",
    })).status).toBe(409);
  });

  it("keeps synthetic Fixture mailboxes out of consumer mode and enables them only through the resolved development entitlement", async () => {
    const consumer = await start();
    const denied = await mutate(consumer, "/api/accounts/connect", {
      provider: "gmail",
      mode: "fixture",
      label: "must-not-exist",
    });
    expect(denied.status).toBe(403);
    expect((await denied.json()).error).toMatch(/development-entitled/i);

    const developer = await listen(createLocalDesktopServer({
      security: new LocalSecurityManager(),
      developmentEntitlementsEnabled: true,
    }));
    const connected = await mutate(developer, "/api/accounts/connect", {
      provider: "gmail",
      mode: "fixture",
      label: "explicit-developer-fixture",
    });
    expect(connected.status).toBe(200);
    const body = await connected.json();
    expect(body).toMatchObject({ provider: "gmail", mode: "fixture" });
    expect(typeof body.accountId).toBe("string");
    expect((await mutate(developer, `/api/accounts/${encodeURIComponent(body.accountId)}`, {}, "DELETE")).status).toBe(204);
  });

  it("rejects malformed account-connect input before any provider attempt", async () => {
    const context = await start();
    const malformed = [
      { provider: "smtp", mode: "live", credentials: {} },
      { provider: "imap", mode: "sideways", credentials: {} },
      { provider: "imap", mode: "live", credentials: { host: "mail.example", port: "70000", secure: "true", user: "u", appPassword: "p" } },
      { provider: "imap", mode: "live", credentials: { host: "mail.example", port: "993", secure: "maybe", user: "u", appPassword: "p" } },
      { provider: "gmail", mode: "fixture", credentials: { refreshToken: "fixture-must-not-carry-secrets" } },
      { provider: "gmail", mode: "fixture", unexpected: true },
    ];

    for (const body of malformed) {
      const response = await mutate(context, "/api/accounts/connect", body);
      expect(response.status).toBe(400);
      const payload = await response.json();
      expect(String(payload.error)).not.toContain("Failed to connect");
    }
  });

  it("does not register developer execution in consumer mode and contains runner failures when explicitly enabled", async () => {
    const consumerUrl = await listenBaseUrl(createServer({ developerToolsEnabled: false }));
    expect((await fetch(`${consumerUrl}/api/dev/test-suite`)).status).toBe(404);

    const marker = "developer-runner-secret-marker";
    const developerUrl = await listenBaseUrl(createServer({
      developerToolsEnabled: true,
      developerTestSuiteRunner: async () => { throw new Error(marker); },
    }));
    const failed = await fetch(`${developerUrl}/api/dev/test-suite`);
    expect(failed.status).toBe(500);
    const failureBody = await failed.text();
    expect(failureBody).toContain("failed safely");
    expect(failureBody).not.toContain(marker);

    expect((await fetch(developerUrl)).status).toBe(200);
  });

  it("consumes a successful opaque action token before it can be replayed", async () => {
    const context = await startActionHarness();
    const actionToken = "11111111-1111-4111-8111-111111111111";

    const first = await mutate(context, "/api/action", { token: actionToken });
    expect(first.status).toBe(200);

    const replay = await mutate(context, "/api/action", { token: actionToken });
    expect(replay.status).toBe(409);
    expect((await replay.json()).error).toContain("already been used");
  });

  it("redacts exact credentials, OAuth parameters, bearer values, and JWT-like tokens", () => {
    const secret = "example-app-password";
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.aSflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const result = redactSensitiveText(
      `failed password=${secret} Bearer abc.def-123? access_token=token-value code=oauth-code ${jwt}`,
      [secret],
    );
    expect(result).not.toContain(secret);
    expect(result).not.toContain("token-value");
    expect(result).not.toContain("oauth-code");
    expect(result).not.toContain(jwt);
    expect(result).toContain("[REDACTED]");
  });
});