import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { createConsumerDesktopServer } from "../../server/src/api/consumerDesktopServer.js";
import { LocalSecurityManager } from "../../server/src/api/localSecurity.js";
import { CommunityNetwork } from "../../server/src/community/network.js";
import { AccountPlatformService } from "../../server/src/platform/accountFamilyService.js";
import { InMemoryAccountPlatformRepository } from "../../server/src/platform/accountFamilyPersistence.js";
import { AccountLifecycleService } from "../../server/src/platform/accountLifecycleService.js";
import type { DeviceIdentityPort } from "../../server/src/platform/accountFamilyPorts.js";
import { deriveDeviceId, type DevicePublicIdentity } from "../../server/src/platform/accountFamilyTypes.js";
import { NodeAccountPlatformRuntime } from "../../server/src/platform/desktopDeviceIdentity.js";

interface BrowserContext {
  baseUrl: string;
  cookie: string;
  csrf: string;
}

const servers: Server[] = [];
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  while (roots.length) rmSync(roots.pop()!, { recursive: true, force: true });
});

function identityPort(): DeviceIdentityPort & { currentDeviceId(): Promise<string> } {
  const pair = generateKeyPairSync("ed25519");
  const identity: DevicePublicIdentity = {
    algorithm: "ed25519",
    publicKeySpki: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    platform: "desktop",
    label: "Lifecycle desktop",
  };
  return {
    currentPublicIdentity: async () => structuredClone(identity),
    currentDeviceId: async () => deriveDeviceId(identity),
    signChallenge: async () => "unused-local-signature",
  };
}

async function start(): Promise<BrowserContext> {
  const dataDirectory = mkdtempSync(join(tmpdir(), "email-shield-lifecycle-api-"));
  roots.push(dataDirectory);
  const repository = new InMemoryAccountPlatformRepository();
  const runtime = new NodeAccountPlatformRuntime();
  const identity = identityPort();
  const accountPlatform = new AccountPlatformService(repository, runtime);
  const currentIdentity = await identity.currentPublicIdentity();
  accountPlatform.createAccount("local.lifecycle", currentIdentity);
  const app = createConsumerDesktopServer({
    security: new LocalSecurityManager(),
    community: new CommunityNetwork({ dataDirectory }),
    accountPlatform,
    accountLifecycle: new AccountLifecycleService(repository, runtime),
    deviceIdentity: identity,
  });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
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

function protectedHeaders(context: BrowserContext, extra: Record<string, string> = {}): Record<string, string> {
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
  const body = await response.json() as { nonce: string };
  expect(body.nonce.length).toBeGreaterThan(20);
  return body.nonce;
}

async function mutation(
  context: BrowserContext,
  path: string,
  method = "POST",
  body: Record<string, unknown> = {},
) {
  return fetch(`${context.baseUrl}${path}`, {
    method,
    headers: protectedHeaders(context, {
      "Content-Type": "application/json",
      "X-Email-Shield-Nonce": await nonce(context),
    }),
    body: JSON.stringify(body),
  });
}

describe("protected local account lifecycle API", () => {
  it("rejects missing local session and cross-origin metadata export", async () => {
    const context = await start();
    expect((await fetch(`${context.baseUrl}/api/profile/v1/export`)).status).toBe(401);
    expect((await fetch(`${context.baseUrl}/api/profile/v1/export`, {
      headers: {
        Cookie: context.cookie,
        "X-Email-Shield-CSRF": context.csrf,
        Origin: "http://127.0.0.1:65531",
      },
    })).status).toBe(403);
  });

  it("exports only privacy-safe profile metadata", async () => {
    const context = await start();
    const response = await fetch(`${context.baseUrl}/api/profile/v1/export`, {
      headers: protectedHeaders(context),
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toContain("no-store");
    const body = await response.json();
    const serialized = JSON.stringify(body);
    expect(body.privacy).toBe("no_recovery_hash_no_public_keys_no_mailbox_identity_no_mail_content");
    expect(serialized).not.toMatch(/recoveryCodeHash|publicKeySpki|mailboxAccountKey|subject|bodyText/i);
  });

  it("requires a one-use mutation authorization before recovery rotation", async () => {
    const context = await start();
    const missingNonce = await fetch(`${context.baseUrl}/api/profile/v1/recovery/rotate`, {
      method: "POST",
      headers: protectedHeaders(context, { "Content-Type": "application/json" }),
      body: "{}",
    });
    expect(missingNonce.status).toBe(409);

    const rotated = await mutation(context, "/api/profile/v1/recovery/rotate");
    expect(rotated.status).toBe(200);
    const body = await rotated.json();
    expect(typeof body.recoveryCode).toBe("string");
    expect(body.recoveryCode.length).toBeGreaterThan(20);
  });

  it("consumes the mutation nonce even when destructive confirmation is wrong", async () => {
    const context = await start();
    const oneTime = await nonce(context);
    const headers = protectedHeaders(context, {
      "Content-Type": "application/json",
      "X-Email-Shield-Nonce": oneTime,
    });
    const wrong = await fetch(`${context.baseUrl}/api/profile/v1/account`, {
      method: "DELETE",
      headers,
      body: JSON.stringify({ confirmation: "delete account" }),
    });
    expect(wrong.status).toBe(400);
    const replay = await fetch(`${context.baseUrl}/api/profile/v1/account`, {
      method: "DELETE",
      headers,
      body: JSON.stringify({ confirmation: "DELETE ACCOUNT" }),
    });
    expect(replay.status).toBe(409);
  });

  it("deletes the Email Shield profile without claiming to delete provider mailbox data", async () => {
    const context = await start();
    const response = await mutation(
      context,
      "/api/profile/v1/account",
      "DELETE",
      { confirmation: "DELETE ACCOUNT" },
    );
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.mailboxContentDeleted).toBe(false);
    expect(body.localMailboxConnectionsDeleted).toBe(false);
    expect(body.deletedAccountId).toMatch(/^acct_/);

    const exportAfter = await fetch(`${context.baseUrl}/api/profile/v1/export`, {
      headers: protectedHeaders(context),
    });
    expect(exportAfter.status).toBe(400);
  });
});
