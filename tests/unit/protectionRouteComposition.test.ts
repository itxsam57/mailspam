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

async function start(): Promise<Context> {
  const app = createLocalDesktopServer({ security: new LocalSecurityManager() });
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

function headers(context: Context, extra: Record<string, string> = {}) {
  return {
    Cookie: context.cookie,
    Origin: context.baseUrl,
    Referer: `${context.baseUrl}/`,
    "X-Email-Shield-CSRF": context.csrf,
    ...extra,
  };
}

async function nonce(context: Context): Promise<string> {
  const response = await fetch(`${context.baseUrl}/api/security/mutation-token`, { method: "POST", headers: headers(context) });
  expect(response.status).toBe(200);
  return (await response.json()).nonce as string;
}

async function mutate(context: Context, path: string, body: unknown) {
  return fetch(`${context.baseUrl}${path}`, {
    method: "POST",
    headers: headers(context, {
      "Content-Type": "application/json",
      "X-Email-Shield-Nonce": await nonce(context),
    }),
    body: JSON.stringify(body),
  });
}

describe("desktop durable protection route composition", () => {
  it("intercepts legacy raw-address Block requests and requires an opaque scan token", async () => {
    const context = await start();
    const connected = await mutate(context, "/api/accounts/connect", { provider: "gmail", mode: "fixture", label: "route-order" });
    expect(connected.status).toBe(200);
    const accountId = (await connected.json()).accountId as string;

    const rawAddressAttempt = await mutate(context, `/api/accounts/${accountId}/messages/block-sender`, {
      address: "attacker@example.test",
    });
    expect(rawAddressAttempt.status).toBe(400);
    expect((await rawAddressAttempt.json()).error).toMatch(/review action token/i);

    const policy = await fetch(`${context.baseUrl}/api/accounts/${accountId}/personal-policy`, { headers: headers(context) });
    expect(policy.status).toBe(200);
    expect((await policy.json()).blockedSenders).not.toContain("attacker@example.test");
  });
});
