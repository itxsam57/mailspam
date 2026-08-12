import { afterEach, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createLocalDesktopServer } from "../../server/src/api/localDesktopServer.js";
import { LocalSecurityManager } from "../../server/src/api/localSecurity.js";

interface Context { baseUrl: string; cookie: string; csrf: string; }
const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

async function start(developmentEntitlementsEnabled = false): Promise<Context> {
  const app = createLocalDesktopServer({
    security: new LocalSecurityManager(),
    developmentEntitlementsEnabled,
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

function protectedHeaders(context: Context, extra: Record<string, string> = {}) {
  return {
    Cookie: context.cookie,
    Origin: context.baseUrl,
    Referer: `${context.baseUrl}/`,
    "X-Email-Shield-CSRF": context.csrf,
    ...extra,
  };
}

async function nonce(context: Context): Promise<string> {
  const response = await fetch(`${context.baseUrl}/api/security/mutation-token`, {
    method: "POST",
    headers: protectedHeaders(context),
  });
  expect(response.status).toBe(200);
  return (await response.json()).nonce as string;
}

async function mutate(context: Context, path: string, body: unknown, method = "POST") {
  return fetch(`${context.baseUrl}${path}`, {
    method,
    headers: protectedHeaders(context, {
      "Content-Type": "application/json",
      "X-Email-Shield-Nonce": await nonce(context),
    }),
    body: method === "DELETE" ? undefined : JSON.stringify(body),
  });
}

describe("protected Email Shield account and Family Shield API", () => {
  it("requires the same local session/CSRF boundary as mailbox APIs", async () => {
    const context = await start();
    expect((await fetch(`${context.baseUrl}/api/profile/v1/snapshot`)).status).toBe(401);
    expect((await fetch(`${context.baseUrl}/api/profile/v1/snapshot`, { headers: { Cookie: context.cookie } })).status).toBe(403);
    expect((await fetch(`${context.baseUrl}/api/profile/v1/snapshot`, { headers: protectedHeaders(context) })).status).toBe(200);
    expect((await fetch(`${context.baseUrl}/api/profile/v1/accounts`, {
      method: "POST",
      headers: protectedHeaders(context, { "Content-Type": "application/json" }),
      body: JSON.stringify({ username: "no.nonce" }),
    })).status).toBe(409);
  });

  it("returns a recovery code once but never exposes recovery hash/private key in snapshots", async () => {
    const context = await start();
    const create = await mutate(context, "/api/profile/v1/accounts", { username: "desktop.user", deviceLabel: "Desktop A" });
    expect(create.status).toBe(201);
    const created = await create.json();
    expect(created.recoveryCode).toMatch(/^[A-Za-z0-9_-]{24,}$/);
    const snapshotResponse = await fetch(`${context.baseUrl}/api/profile/v1/snapshot`, { headers: protectedHeaders(context) });
    const snapshot = await snapshotResponse.json();
    expect(snapshot.account.username).toBe("desktop.user");
    expect(snapshot.account.devices).toHaveLength(1);
    const serialized = JSON.stringify(snapshot);
    for (const forbidden of ["recoveryCode", "recoveryCodeHash", "privateKey", "privateKeyPkcs8", "appPassword", "refreshToken"]) {
      expect(serialized).not.toContain(forbidden);
    }
  });

  it("refuses client-side premium switching unless the explicit local development gate is enabled", async () => {
    const productionLike = await start(false);
    await mutate(productionLike, "/api/profile/v1/accounts", { username: "plan.user", deviceLabel: "Desktop" });
    const rejected = await mutate(productionLike, "/api/profile/v1/entitlement/development", { plan: "family" });
    expect(rejected.status).toBe(403);

    const acceptance = await start(true);
    await mutate(acceptance, "/api/profile/v1/accounts", { username: "preview.user", deviceLabel: "Desktop" });
    const switched = await mutate(acceptance, "/api/profile/v1/entitlement/development", { plan: "family" });
    expect(switched.status).toBe(200);
    const result = await switched.json();
    expect(result).toMatchObject({ previewOnly: true, source: "development" });
    expect(result.snapshot.account.entitlement).toMatchObject({ plan: "family", source: "development", seatLimit: 6 });
  });

  it("creates a six-seat Family Shield circle only after Family entitlement", async () => {
    const context = await start(true);
    await mutate(context, "/api/profile/v1/accounts", { username: "family.api.owner", deviceLabel: "Desktop" });
    expect((await mutate(context, "/api/profile/v1/family", {})).status).toBe(400);
    expect((await mutate(context, "/api/profile/v1/entitlement/development", { plan: "family" })).status).toBe(200);
    const created = await mutate(context, "/api/profile/v1/family", {});
    expect(created.status).toBe(201);
    const family = await created.json();
    expect(family.family).toMatchObject({ seatLimit: 6, seatsUsed: 1, strictProtection: false });
    const invite = await mutate(context, "/api/profile/v1/family/invites", {});
    expect(invite.status).toBe(201);
    const inviteBody = await invite.json();
    expect(inviteBody.inviteCode).toMatch(/^[A-Za-z0-9_-]{24,}$/);
    expect(JSON.stringify(inviteBody)).not.toMatch(/subject|body|mailbox|providerNativeId|senderAddress/i);
  });
});
