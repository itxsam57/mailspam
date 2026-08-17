import { afterEach, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
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
  await Promise.all(
    servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
  );
});

async function openDashboard(): Promise<BrowserContext> {
  const app = createLocalDesktopServer({
    security: new LocalSecurityManager(),
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

async function mutationNonce(context: BrowserContext): Promise<string> {
  const response = await fetch(`${context.baseUrl}/api/security/mutation-token`, {
    method: "POST",
    headers: protectedHeaders(context),
  });
  expect(response.status).toBe(200);
  return (await response.json()).nonce as string;
}

async function mutate(
  context: BrowserContext,
  path: string,
  body: unknown = {},
  method: "POST" | "DELETE" = "POST",
): Promise<Response> {
  return fetch(`${context.baseUrl}${path}`, {
    method,
    headers: protectedHeaders(context, {
      "Content-Type": "application/json",
      "X-Email-Shield-Nonce": await mutationNonce(context),
    }),
    body: method === "DELETE" ? undefined : JSON.stringify(body),
  });
}

async function connectGmailFixture(context: BrowserContext, label: string): Promise<string> {
  const response = await mutate(context, "/api/accounts/connect", {
    provider: "gmail",
    mode: "fixture",
    label,
  });
  expect(response.status).toBe(200);
  const accountId = (await response.json()).accountId as string;
  accountIds.push(accountId);
  return accountId;
}

describe("superseded reconnect session API reachability", () => {
  it("rejects stale IDs for fresh work while preserving stop/disconnect cleanup", async () => {
    const context = await openDashboard();
    const staleId = await connectGmailFixture(context, "gmail-before-reconnect");
    const canonicalId = await connectGmailFixture(context, "gmail-after-reconnect");

    const stale = sessionStore.get(staleId);
    const canonical = sessionStore.getCanonical(canonicalId);
    expect(stale).toBeDefined();
    expect(canonical).toBeDefined();
    expect(stale?.policyAccountKey).toBe(canonical?.policyAccountKey);
    expect(sessionStore.getCanonical(staleId)).toBeUndefined();

    const staleBackground = await fetch(
      `${context.baseUrl}/api/accounts/${encodeURIComponent(staleId)}/background-protection`,
      { headers: protectedHeaders(context) },
    );
    expect(staleBackground.status).toBe(404);

    const stalePolicyExport = await fetch(
      `${context.baseUrl}/api/accounts/${encodeURIComponent(staleId)}/personal-policy/export`,
      { headers: protectedHeaders(context) },
    );
    expect(stalePolicyExport.status).toBe(404);

    const staleMessageAction = await mutate(
      context,
      `/api/accounts/${encodeURIComponent(staleId)}/messages/mark-safe`,
      { token: "stale-tab-token" },
    );
    expect(staleMessageAction.status).toBe(404);

    const staleScan = await fetch(
      `${context.baseUrl}/api/accounts/${encodeURIComponent(staleId)}/scan/quick`,
      {
        headers: {
          Cookie: context.cookie,
          Referer: `${context.baseUrl}/`,
          Accept: "text/event-stream",
        },
      },
    );
    if (staleScan.body) await staleScan.body.cancel().catch(() => undefined);
    expect(staleScan.status).toBe(404);

    // Cleanup remains deliberately broad so an obsolete tab/session can be
    // stopped and disconnected without making stale credentials immortal.
    const stopped = await mutate(
      context,
      `/api/accounts/${encodeURIComponent(staleId)}/scan/stop`,
    );
    expect(stopped.status).toBe(200);

    const disconnected = await mutate(
      context,
      `/api/accounts/${encodeURIComponent(staleId)}`,
      {},
      "DELETE",
    );
    expect(disconnected.status).toBe(204);
    accountIds.splice(accountIds.indexOf(staleId), 1);

    expect(sessionStore.get(staleId)).toBeUndefined();
    expect(sessionStore.getCanonical(canonicalId)?.id).toBe(canonicalId);

    const canonicalBackground = await fetch(
      `${context.baseUrl}/api/accounts/${encodeURIComponent(canonicalId)}/background-protection`,
      { headers: protectedHeaders(context) },
    );
    expect(canonicalBackground.status).toBe(200);
  });
});
