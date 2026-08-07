import { afterEach, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createLocalDesktopServer } from "../../server/src/api/localDesktopServer.js";
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
  const app = createLocalDesktopServer({ security: new LocalSecurityManager() });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", () => resolve()));
  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;
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

async function mutate(context: BrowserContext, path: string, body: unknown): Promise<Response> {
  return fetch(`${context.baseUrl}${path}`, {
    method: "POST",
    headers: protectedHeaders(context, {
      "Content-Type": "application/json",
      "X-Email-Shield-Nonce": await nonce(context),
    }),
    body: JSON.stringify(body),
  });
}

describe("reversible personal blocks", () => {
  it("removes exact sender and domain blocks through protected account-scoped mutations", async () => {
    const context = await start();
    const connected = await mutate(context, "/api/accounts/connect", {
      provider: "gmail",
      mode: "fixture",
      label: "policy-undo-test",
    });
    expect(connected.status).toBe(200);
    const accountId = (await connected.json()).accountId as string;
    const address = `undo-${Date.now()}@example.com`;
    const domain = "undo-policy.example.com";

    expect((await mutate(context, `/api/accounts/${accountId}/messages/block-sender`, { address })).status).toBe(200);
    expect((await mutate(context, `/api/accounts/${accountId}/messages/block-domain`, { domain })).status).toBe(200);

    let policyResponse = await fetch(`${context.baseUrl}/api/accounts/${accountId}/personal-policy`, {
      headers: protectedHeaders(context),
    });
    expect(policyResponse.status).toBe(200);
    let policy = await policyResponse.json();
    expect(policy.blockedSenders).toContain(address);
    expect(policy.blockedDomains).toContain(domain);

    const senderUndo = await mutate(context, `/api/accounts/${accountId}/messages/unblock-sender`, { address });
    expect(senderUndo.status).toBe(200);
    expect(await senderUndo.json()).toMatchObject({ blocked: false, scope: "sender", value: address, accountId });

    const domainUndo = await mutate(context, `/api/accounts/${accountId}/messages/unblock-domain`, { domain });
    expect(domainUndo.status).toBe(200);
    expect(await domainUndo.json()).toMatchObject({ blocked: false, scope: "domain", value: domain, accountId });

    policyResponse = await fetch(`${context.baseUrl}/api/accounts/${accountId}/personal-policy`, {
      headers: protectedHeaders(context),
    });
    policy = await policyResponse.json();
    expect(policy.blockedSenders).not.toContain(address);
    expect(policy.blockedDomains).not.toContain(domain);
  });
});
