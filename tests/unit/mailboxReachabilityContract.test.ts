import { afterEach, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import type { AccountSession } from "../../server/src/api/sessionStore.js";
import { createLocalDesktopServer } from "../../server/src/api/localDesktopServer.js";
import { LocalSecurityManager } from "../../server/src/api/localSecurity.js";
import { sessionStore } from "../../server/src/api/sessionStore.js";
import { InMemoryInboundEventStateRepository } from "../../server/src/realtime/inboundEvents.js";
import { RealtimeProtectionService } from "../../server/src/realtime/realtimeProtectionService.js";

const REPOSITORY_ROOT = basename(process.cwd()) === "server"
  ? resolve(process.cwd(), "..")
  : process.cwd();

interface ReachabilitySnapshot {
  state: "checking" | "reachable" | "unavailable" | "unknown";
  checkedAt: number | null;
  lastReachableAt: number | null;
}

function realtimeSession(id: string, accountKey = "a".repeat(64)): AccountSession {
  return {
    id,
    provider: "gmail",
    label: "fixture",
    config: { provider: "gmail", mode: "fixture", fixtureFolderOverrides: {} },
    activeScanWorker: null,
    personalPolicy: {} as AccountSession["personalPolicy"],
    policyAccountKey: accountKey,
    vaultReferences: [],
    closing: false,
    unsubscribeActions: new Map(),
    reviewActions: new Map(),
  } as AccountSession;
}

function reachabilityReader(service: RealtimeProtectionService) {
  return service as unknown as {
    mailboxReachability(session: AccountSession): ReachabilitySnapshot;
  };
}

const servers: Server[] = [];
const accountIds: string[] = [];

afterEach(async () => {
  for (const id of accountIds.splice(0)) {
    try { await sessionStore.remove(id); } catch {}
  }
  await Promise.all(
    servers.splice(0).map((server) => new Promise<void>((resolveClose) => server.close(() => resolveClose()))),
  );
});

async function openDashboard(options: Record<string, unknown>) {
  const app = createLocalDesktopServer({
    security: new LocalSecurityManager(),
    developmentEntitlementsEnabled: true,
    ...options,
  } as never);
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolveListen) => server.once("listening", resolveListen));
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const home = await fetch(baseUrl);
  const html = await home.text();
  return {
    baseUrl,
    cookie: home.headers.get("set-cookie")?.split(";", 1)[0] ?? "",
    csrf: html.match(/<meta name="email-shield-csrf" content="([^"]+)"/)?.[1] ?? "",
  };
}

function protectedHeaders(context: { baseUrl: string; cookie: string; csrf: string }, extra: Record<string, string> = {}) {
  return {
    Cookie: context.cookie,
    Origin: context.baseUrl,
    Referer: `${context.baseUrl}/`,
    "X-Email-Shield-CSRF": context.csrf,
    ...extra,
  };
}

async function mutationNonce(context: { baseUrl: string; cookie: string; csrf: string }): Promise<string> {
  const response = await fetch(`${context.baseUrl}/api/security/mutation-token`, {
    method: "POST",
    headers: protectedHeaders(context),
  });
  expect(response.status).toBe(200);
  return (await response.json()).nonce as string;
}

async function connectFixture(context: { baseUrl: string; cookie: string; csrf: string }): Promise<string> {
  const response = await fetch(`${context.baseUrl}/api/accounts/connect`, {
    method: "POST",
    headers: protectedHeaders(context, {
      "Content-Type": "application/json",
      "X-Email-Shield-Nonce": await mutationNonce(context),
    }),
    body: JSON.stringify({ provider: "gmail", mode: "fixture", label: "reachability-fixture" }),
  });
  expect(response.status).toBe(200);
  const accountId = (await response.json()).accountId as string;
  accountIds.push(accountId);
  return accountId;
}

describe("mailbox reachability contract", () => {
  it("derives session-bound reachability from the existing metadata probe without inheriting stale reconnect health", async () => {
    const first = realtimeSession("session-before-reconnect");
    const replacement = realtimeSession("session-after-reconnect", first.policyAccountKey);
    let active = first;
    let failProbe = false;
    const service = new RealtimeProtectionService({
      sessions: { list: () => [active] },
      repository: new InMemoryInboundEventStateRepository(),
      pollProbe: {
        checkpoint: async () => {
          if (failProbe) throw new Error("SECRET provider OAuth refresh failure");
          return "checkpoint-one";
        },
      },
      processor: {
        process: async () => ({ examined: 0, warnings: 0, highRisk: 0, confirmedThreat: 0 }),
      },
    });
    const reader = reachabilityReader(service);

    expect(typeof reader.mailboxReachability).toBe("function");
    expect(reader.mailboxReachability(first)).toEqual({
      state: "checking",
      checkedAt: null,
      lastReachableAt: null,
    });

    await service.pollNow(1_000);
    expect(reader.mailboxReachability(first)).toEqual({
      state: "reachable",
      checkedAt: 1_000,
      lastReachableAt: 1_000,
    });

    active = replacement;
    expect(reader.mailboxReachability(replacement)).toEqual({
      state: "checking",
      checkedAt: null,
      lastReachableAt: null,
    });

    failProbe = true;
    await service.pollNow(2_000);
    const unavailable = reader.mailboxReachability(replacement);
    expect(unavailable).toEqual({
      state: "unavailable",
      checkedAt: 2_000,
      lastReachableAt: null,
    });
    expect(Object.keys(unavailable).sort()).toEqual(["checkedAt", "lastReachableAt", "state"]);
    expect(JSON.stringify(unavailable)).not.toContain("SECRET");
    expect(JSON.stringify(unavailable)).not.toContain("checkpoint-one");
  });

  it("publishes only fixed sanitized reachability fields through /api/accounts", async () => {
    const context = await openDashboard({
      accountReachability: () => ({
        state: "unavailable",
        checkedAt: 1_234,
        lastReachableAt: null,
        rawError: "SECRET refresh token rejected",
        checkpoint: "SECRET checkpoint digest",
      }),
    });
    const accountId = await connectFixture(context);

    const response = await fetch(`${context.baseUrl}/api/accounts`, {
      headers: protectedHeaders(context),
      cache: "no-store",
    });
    expect(response.status).toBe(200);
    const accounts = await response.json() as Array<Record<string, unknown>>;
    const account = accounts.find((entry) => entry.accountId === accountId);
    expect(account).toBeDefined();
    expect(account?.reachability).toEqual({
      state: "unavailable",
      checkedAt: 1_234,
      lastReachableAt: null,
    });
    const serialized = JSON.stringify(account);
    expect(serialized).not.toContain("SECRET");
    expect(serialized).not.toContain("rawError");
    expect(serialized).not.toContain("checkpoint");
  });

  it("wires production account status to the one existing realtime metadata heartbeat", () => {
    const indexSource = readFileSync(resolve(REPOSITORY_ROOT, "server/src/index.ts"), "utf8");
    expect((indexSource.match(/new AdapterMailboxCheckpointProbe\(/g) ?? [])).toHaveLength(1);
    expect(indexSource).toMatch(/accountReachability\s*:\s*\(session\)\s*=>\s*realtimeProtection\.mailboxReachability\(session\)/);
  });
});
