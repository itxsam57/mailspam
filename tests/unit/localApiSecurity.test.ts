import { afterEach, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import { request as httpRequest, type Server } from "node:http";
import { createLocalDesktopServer } from "../../server/src/api/localDesktopServer.js";
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

async function start(): Promise<BrowserContext> {
  const app = createLocalDesktopServer({ security: new LocalSecurityManager() });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", () => resolve()));
  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;
  const home = await fetch(baseUrl);
  const html = await home.text();
  const cookie = home.headers.get("set-cookie")?.split(";", 1)[0] ?? "";
  const csrf = html.match(/<meta name="email-shield-csrf" content="([^"]+)"/)?.[1] ?? "";
  expect(home.status).toBe(200);
  expect(cookie).toMatch(/^email_shield_local_session=/);
  expect(csrf.length).toBeGreaterThanOrEqual(32);
  return { baseUrl, cookie, csrf };
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

  it("rejects account access without both the local session and CSRF proof", async () => {
    const context = await start();
    expect((await fetch(`${context.baseUrl}/api/accounts`)).status).toBe(401);
    expect((await fetch(`${context.baseUrl}/api/accounts`, {
      headers: { Cookie: context.cookie },
    })).status).toBe(403);
    expect((await fetch(`${context.baseUrl}/api/accounts`, {
      headers: headers(context),
    })).status).toBe(200);
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

  it("requires a single-use mutation nonce", async () => {
    const context = await start();
    const mutationNonce = await nonce(context);
    const request = () => fetch(`${context.baseUrl}/api/accounts/connect`, {
      method: "POST",
      headers: headers(context, {
        "Content-Type": "application/json",
        "X-Email-Shield-Nonce": mutationNonce,
      }),
      body: JSON.stringify({ provider: "gmail", mode: "fixture", label: "nonce-test" }),
    });

    expect((await request()).status).toBe(200);
    expect((await request()).status).toBe(409);
    expect((await fetch(`${context.baseUrl}/api/accounts/connect`, {
      method: "POST",
      headers: headers(context, { "Content-Type": "application/json" }),
      body: JSON.stringify({ provider: "gmail", mode: "fixture" }),
    })).status).toBe(409);
  });

  it("consumes an opaque message action after the provider confirms success", async () => {
    const context = await start();
    const connected = await mutate(context, "/api/accounts/connect", {
      provider: "gmail",
      mode: "fixture",
      label: "action-replay-test",
    });
    const account = await connected.json();
    expect(connected.status).toBe(200);

    const scan = await fetch(`${context.baseUrl}/api/accounts/${account.accountId}/scan/quick`, {
      headers: {
        Cookie: context.cookie,
        Origin: context.baseUrl,
        Referer: `${context.baseUrl}/`,
      },
    });
    const stream = await scan.text();
    expect(scan.status).toBe(200);
    expect(stream).toContain('"reviewAction"');
    const actionToken = stream.match(/"reviewAction":\{[^}]*"token":"([0-9a-f-]{36})"/i)?.[1];
    expect(actionToken, stream.slice(-2000)).toMatch(/^[0-9a-f-]{36}$/i);

    const first = await mutate(
      context,
      `/api/accounts/${account.accountId}/messages/report-spam`,
      { token: actionToken },
    );
    expect(first.status).toBe(200);

    const replay = await mutate(
      context,
      `/api/accounts/${account.accountId}/messages/report-spam`,
      { token: actionToken },
    );
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
