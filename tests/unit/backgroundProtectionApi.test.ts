import { afterEach, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { BackgroundProtectionCoordinator } from "../../server/src/api/backgroundProtection.js";
import { InMemoryBackgroundProtectionRepository } from "../../server/src/api/backgroundProtectionPersistence.js";
import { createLocalDesktopServer } from "../../server/src/api/localDesktopServer.js";
import { LocalSecurityManager } from "../../server/src/api/localSecurity.js";
import { sessionStore } from "../../server/src/api/sessionStore.js";

interface BrowserContext {
  baseUrl: string;
  cookie: string;
  csrf: string;
}

const servers: Server[] = [];
const accountIds: string[] = [];

afterEach(async () => {
  for (const id of accountIds.splice(0)) {
    try { await sessionStore.remove(id); } catch {}
  }
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

async function start(coordinator: BackgroundProtectionCoordinator): Promise<BrowserContext> {
  const app = createLocalDesktopServer({
    security: new LocalSecurityManager(),
    backgroundProtection: coordinator,
    developmentEntitlementsEnabled: true,
  });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const home = await fetch(baseUrl);
  const html = await home.text();
  return {
    baseUrl,
    cookie: home.headers.get("set-cookie")?.split(";", 1)[0] ?? "",
    csrf: html.match(/<meta name="email-shield-csrf" content="([^"]+)"/)?.[1] ?? "",
  };
}

function protectedHeaders(context: BrowserContext, extra: Record<string, string> = {}) {
  return {
    Cookie: context.cookie,
    Origin: context.baseUrl,
    Referer: `${context.baseUrl}/`,
    "X-Email-Shield-CSRF": context.csrf,
    ...extra,
  };
}

async function nonce(context: BrowserContext): Promise<string> {
  const response = await fetch(`${context.baseUrl}/api/security/mutation-token`, {
    method: "POST",
    headers: protectedHeaders(context),
  });
  expect(response.status).toBe(200);
  return (await response.json()).nonce as string;
}

async function mutate(context: BrowserContext, path: string, method: "POST" | "DELETE", body?: unknown): Promise<Response> {
  return fetch(`${context.baseUrl}${path}`, {
    method,
    headers: protectedHeaders(context, {
      "Content-Type": "application/json",
      "X-Email-Shield-Nonce": await nonce(context),
    }),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function connectFixture(context: BrowserContext, provider: "gmail" | "outlook"): Promise<string> {
  const response = await mutate(context, "/api/accounts/connect", "POST", { provider, mode: "fixture" });
  expect(response.status).toBe(200);
  const accountId = (await response.json()).accountId as string;
  accountIds.push(accountId);
  return accountId;
}

describe("background protection account API", () => {
  it("requires protected reads/mutations, isolates schedules and removes state on disconnect", async () => {
    const repository = new InMemoryBackgroundProtectionRepository();
    const coordinator = new BackgroundProtectionCoordinator({
      repository,
      sessions: sessionStore,
      executor: { execute: async () => undefined },
    });
    const context = await start(coordinator);
    const firstId = await connectFixture(context, "gmail");
    const secondId = await connectFixture(context, "outlook");
    const first = sessionStore.get(firstId)!;

    const unprotected = await fetch(`${context.baseUrl}/api/accounts/${firstId}/background-protection`, {
      headers: { Cookie: context.cookie, Origin: context.baseUrl, Referer: `${context.baseUrl}/` },
    });
    expect(unprotected.status).toBe(403);

    const missingNonce = await fetch(`${context.baseUrl}/api/accounts/${firstId}/background-protection`, {
      method: "POST",
      headers: protectedHeaders(context, { "Content-Type": "application/json" }),
      body: JSON.stringify({ enabled: true, intervalMinutes: 60 }),
    });
    // The authenticated same-origin request reached the one-time mutation
    // authorization boundary, where a missing/replayed nonce is a conflict.
    expect(missingNonce.status).toBe(409);

    const enabled = await mutate(
      context,
      `/api/accounts/${firstId}/background-protection`,
      "POST",
      { enabled: true, intervalMinutes: 60 },
    );
    expect(enabled.status).toBe(200);
    expect(await enabled.json()).toMatchObject({
      enabled: true,
      intervalMinutes: 60,
      status: "scheduled",
      persistent: false,
      limits: { maximumConcurrentScans: 1, maximumMessagesPerRun: 20 },
    });

    const secondStatus = await fetch(`${context.baseUrl}/api/accounts/${secondId}/background-protection`, {
      headers: protectedHeaders(context),
    });
    expect(await secondStatus.json()).toMatchObject({ enabled: false, status: "paused" });
    expect(repository.get(first.policyAccountKey)).not.toBeNull();

    const disconnected = await mutate(context, `/api/accounts/${firstId}`, "DELETE");
    expect(disconnected.status).toBe(204);
    accountIds.splice(accountIds.indexOf(firstId), 1);
    expect(repository.get(first.policyAccountKey)).toBeNull();
  });

  it("rejects unknown settings and quota-violating intervals", async () => {
    const coordinator = new BackgroundProtectionCoordinator({
      repository: new InMemoryBackgroundProtectionRepository(),
      sessions: sessionStore,
      executor: { execute: async () => undefined },
    });
    const context = await start(coordinator);
    const accountId = await connectFixture(context, "gmail");

    const unknown = await mutate(context, `/api/accounts/${accountId}/background-protection`, "POST", {
      enabled: true,
      intervalMinutes: 60,
      mailbox: "must-not-be-accepted@example.test",
    });
    expect(unknown.status).toBe(400);
    const tooFrequent = await mutate(context, `/api/accounts/${accountId}/background-protection`, "POST", {
      enabled: true,
      intervalMinutes: 5,
    });
    expect(tooFrequent.status).toBe(400);
  });
});