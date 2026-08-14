import { afterEach, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createConsumerDesktopServer } from "../../server/src/api/consumerDesktopServer.js";
import { LocalSecurityManager } from "../../server/src/api/localSecurity.js";

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
  const app = createConsumerDesktopServer({ security: new LocalSecurityManager() });
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

function protectedHeaders(context: BrowserContext, overrides: Record<string, string> = {}) {
  return {
    Cookie: context.cookie,
    Origin: context.baseUrl,
    Referer: `${context.baseUrl}/`,
    "X-Email-Shield-CSRF": context.csrf,
    ...overrides,
  };
}

async function nonce(context: BrowserContext): Promise<string> {
  const response = await fetch(`${context.baseUrl}/api/security/mutation-token`, {
    method: "POST",
    headers: protectedHeaders(context),
  });
  const body = await response.json();
  expect(response.status).toBe(200);
  expect(body.nonce).toMatch(/^[A-Za-z0-9_-]{32,}$/);
  return body.nonce;
}

describe("canonical consumer desktop security composition", () => {
  it("protects consumer reads with local session, CSRF, and same-dashboard provenance", async () => {
    const context = await start();
    const url = `${context.baseUrl}/api/consumer/v1/support-bundle`;

    expect((await fetch(url)).status).toBe(401);
    expect((await fetch(url, { headers: { Cookie: context.cookie } })).status).toBe(403);
    expect((await fetch(url, {
      headers: protectedHeaders(context, {
        Origin: "https://attacker.example",
        Referer: "https://attacker.example/",
        "Sec-Fetch-Site": "cross-site",
      }),
    })).status).toBe(403);

    const accepted = await fetch(url, { headers: protectedHeaders(context) });
    expect(accepted.status).toBe(200);
    const body = await accepted.json();
    expect(body).toMatchObject({ schemaVersion: 1, privacy: expect.any(String) });
    expect(JSON.stringify(body)).not.toMatch(/refreshToken|accessToken|appPassword|providerNativeId|messageId/i);
  });

  it("requires and consumes a one-use mutation nonce before any consumer mutation handler", async () => {
    const context = await start();
    const url = `${context.baseUrl}/api/consumer/v1/browser/check`;
    const body = JSON.stringify({ schemaVersion: 1, url: "javascript:alert(1)", context: "explicit_check" });
    const baseHeaders = protectedHeaders(context, { "Content-Type": "application/json" });

    expect((await fetch(url, { method: "POST", headers: baseHeaders, body })).status).toBe(409);

    const mutationNonce = await nonce(context);
    const authorizedHeaders = { ...baseHeaders, "X-Email-Shield-Nonce": mutationNonce };
    const authorized = await fetch(url, { method: "POST", headers: authorizedHeaders, body });
    expect(authorized.status).toBe(400);

    const replay = await fetch(url, { method: "POST", headers: authorizedHeaders, body });
    expect(replay.status).toBe(409);
  });

  it("keeps Scam Check read-only analysis behind session, CSRF, same-origin and its own bounded parser", async () => {
    const context = await start();
    const url = `${context.baseUrl}/api/scam-check/v1/analyze`;
    const body = JSON.stringify({ schemaVersion: 1, kind: "message", text: "A harmless local test message." });

    expect((await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    })).status).toBe(401);

    expect((await fetch(url, {
      method: "POST",
      headers: protectedHeaders(context, {
        "Content-Type": "application/json",
        Origin: "https://attacker.example",
        Referer: "https://attacker.example/",
        "Sec-Fetch-Site": "cross-site",
      }),
      body,
    })).status).toBe(403);

    const accepted = await fetch(url, {
      method: "POST",
      headers: protectedHeaders(context, { "Content-Type": "application/json" }),
      body,
    });
    expect(accepted.status).toBe(200);
    const result = await accepted.json();
    expect(result).toMatchObject({ schemaVersion: 1, verdict: expect.any(String) });
  });

  it("applies the consumer mutation guard before media-authenticity body parsing", async () => {
    const context = await start();
    const url = `${context.baseUrl}/api/consumer/v1/media/authenticity`;
    const baseHeaders = protectedHeaders(context, { "Content-Type": "application/json" });

    expect((await fetch(url, { method: "POST", headers: baseHeaders, body: "{}" })).status).toBe(409);

    const mutationNonce = await nonce(context);
    const authorized = await fetch(url, {
      method: "POST",
      headers: { ...baseHeaders, "X-Email-Shield-Nonce": mutationNonce },
      body: "{}",
    });
    expect([400, 415]).toContain(authorized.status);

    const replay = await fetch(url, {
      method: "POST",
      headers: { ...baseHeaders, "X-Email-Shield-Nonce": mutationNonce },
      body: "{}",
    });
    expect(replay.status).toBe(409);
  });
});