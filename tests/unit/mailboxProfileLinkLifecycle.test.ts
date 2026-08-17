import { afterEach, describe, expect, it, vi } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import type { AccountPlatformRepository, AccountPlatformRuntime } from "../../server/src/platform/accountFamilyPorts.js";
import type { AccountPlatformState } from "../../server/src/platform/accountFamilyTypes.js";
import { defaultFreeEntitlement } from "../../server/src/platform/accountFamilyTypes.js";
import { AccountPlatformService } from "../../server/src/platform/accountFamilyService.js";
import { AccountLifecycleService } from "../../server/src/platform/accountLifecycleService.js";
import { createLocalDesktopServer } from "../../server/src/api/localDesktopServer.js";
import { LocalSecurityManager } from "../../server/src/api/localSecurity.js";
import { sessionStore } from "../../server/src/api/sessionStore.js";

interface Context { baseUrl: string; cookie: string; csrf: string; }
const servers: Server[] = [];

class MemoryAccountRepository implements AccountPlatformRepository {
  readonly persistent = false;
  constructor(private state: AccountPlatformState) {}
  load(): AccountPlatformState { return structuredClone(this.state); }
  save(state: AccountPlatformState): void { this.state = structuredClone(state); }
}

const deviceId = "dev_" + "1".repeat(64);

function initialState(): AccountPlatformState {
  return {
    schemaVersion: 1,
    currentAccountId: "acct_profile_owner_12345678",
    accounts: [{
      accountId: "acct_profile_owner_12345678",
      username: "profile.owner",
      createdAt: 1,
      recoveryCodeHash: "a".repeat(64),
      devices: [{
        deviceId,
        algorithm: "p256",
        publicKeySpki: "test-public-key",
        platform: "desktop",
        label: "Test desktop",
        createdAt: 1,
        lastSeenAt: 1,
        revokedAt: null,
      }],
      entitlement: defaultFreeEntitlement(1),
      familyCircleId: null,
    }],
    familyCircles: [],
    mailboxLinks: [],
  };
}

function runtime(): AccountPlatformRuntime {
  return {
    now: () => 100,
    id: (prefix) => `${prefix}_test_12345678`,
    secret: () => "x".repeat(32),
  };
}

async function start() {
  const repository = new MemoryAccountRepository(initialState());
  const accountPlatform = new AccountPlatformService(repository, runtime());
  const lifecycle = new AccountLifecycleService(repository, runtime());
  const app = createLocalDesktopServer({
    security: new LocalSecurityManager(),
    accountPlatform,
    developmentEntitlementsEnabled: true,
  });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const home = await fetch(baseUrl);
  const html = await home.text();
  const context: Context = {
    baseUrl,
    cookie: home.headers.get("set-cookie")?.split(";", 1)[0] ?? "",
    csrf: html.match(/<meta name="email-shield-csrf" content="([^"]+)"/)?.[1] ?? "",
  };
  return { context, accountPlatform, lifecycle };
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

async function mutate(context: Context, path: string, body: unknown = {}, method = "POST") {
  return fetch(`${context.baseUrl}${path}`, {
    method,
    headers: protectedHeaders(context, {
      "Content-Type": "application/json",
      "X-Email-Shield-Nonce": await nonce(context),
    }),
    body: method === "DELETE" ? undefined : JSON.stringify(body),
  });
}

async function connectFixture(context: Context, provider = "gmail") {
  const response = await mutate(context, "/api/accounts/connect", {
    provider,
    mode: "fixture",
    label: `ema25-${provider}-${Math.random()}`,
  });
  expect(response.status).toBe(200);
  const body = await response.json();
  const session = sessionStore.get(body.accountId);
  expect(session).toBeTruthy();
  return { accountId: body.accountId as string, accountKey: session!.policyAccountKey };
}

afterEach(async () => {
  vi.restoreAllMocks();
  for (const session of sessionStore.list()) await sessionStore.remove(session.id).catch(() => undefined);
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

describe("EMA-25 mailbox profile-link lifecycle", () => {
  it("removes the active profile link when the final connected mailbox is disconnected", async () => {
    const { context, accountPlatform, lifecycle } = await start();
    const mailbox = await connectFixture(context);
    expect((await mutate(context, `/api/profile/v1/mailboxes/${mailbox.accountId}/link`)).status).toBe(200);
    expect(lifecycle.exportAccountMetadata(deviceId).account.linkedMailboxCount).toBe(1);
    expect(accountPlatform.accountForMailbox(mailbox.accountKey)?.accountId).toBe("acct_profile_owner_12345678");

    expect((await mutate(context, `/api/accounts/${mailbox.accountId}`, {}, "DELETE")).status).toBe(204);

    expect(lifecycle.exportAccountMetadata(deviceId).account.linkedMailboxCount).toBe(0);
    expect(accountPlatform.accountForMailbox(mailbox.accountKey)).toBeNull();
  });

  it("keeps the profile link if provider/session teardown fails", async () => {
    const { context, accountPlatform, lifecycle } = await start();
    const mailbox = await connectFixture(context);
    expect((await mutate(context, `/api/profile/v1/mailboxes/${mailbox.accountId}/link`)).status).toBe(200);
    vi.spyOn(sessionStore, "remove").mockRejectedValueOnce(new Error("simulated disconnect failure"));

    const failed = await mutate(context, `/api/accounts/${mailbox.accountId}`, {}, "DELETE");
    expect(failed.status).toBe(502);
    expect(sessionStore.get(mailbox.accountId)).toBeTruthy();
    expect(lifecycle.exportAccountMetadata(deviceId).account.linkedMailboxCount).toBe(1);
    expect(accountPlatform.accountForMailbox(mailbox.accountKey)?.accountId).toBe("acct_profile_owner_12345678");
  });

  it("does not unlink a mailbox when only a superseded reconnect session is cleaned up", async () => {
    const { context, accountPlatform, lifecycle } = await start();
    const first = await connectFixture(context);
    expect((await mutate(context, `/api/profile/v1/mailboxes/${first.accountId}/link`)).status).toBe(200);
    const replacement = await connectFixture(context);
    expect(replacement.accountKey).toBe(first.accountKey);

    expect((await mutate(context, `/api/accounts/${first.accountId}`, {}, "DELETE")).status).toBe(204);
    expect(lifecycle.exportAccountMetadata(deviceId).account.linkedMailboxCount).toBe(1);
    expect(accountPlatform.accountForMailbox(first.accountKey)?.accountId).toBe("acct_profile_owner_12345678");

    expect((await mutate(context, `/api/accounts/${replacement.accountId}`, {}, "DELETE")).status).toBe(204);
    expect(lifecycle.exportAccountMetadata(deviceId).account.linkedMailboxCount).toBe(0);
    expect(accountPlatform.accountForMailbox(first.accountKey)).toBeNull();
  });
});
