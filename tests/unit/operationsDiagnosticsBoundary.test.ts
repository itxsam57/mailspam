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

async function start(developmentEntitlementsEnabled = false): Promise<BrowserContext> {
  const app = createConsumerDesktopServer({
    security: new LocalSecurityManager(),
    developmentEntitlementsEnabled,
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

function headers(context: BrowserContext): Record<string, string> {
  return {
    Cookie: context.cookie,
    Origin: context.baseUrl,
    Referer: `${context.baseUrl}/`,
    "X-Email-Shield-CSRF": context.csrf,
  };
}

describe("EMA-11 canonical consumer operations diagnostics HTTP boundary", () => {
  it("does not advertise the internal operations snapshot in ordinary consumer mode", async () => {
    const consumer = await start(false);
    expect((await fetch(`${consumer.baseUrl}/api/operations/v1/snapshot`, { headers: headers(consumer) })).status).toBe(404);
  });

  it("keeps aggregate-only diagnostics available when development entitlement is resolved", async () => {
    const developer = await start(true);
    const response = await fetch(`${developer.baseUrl}/api/operations/v1/snapshot`, { headers: headers(developer) });
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = await response.json();
    expect(body).toMatchObject({
      schemaVersion: 1,
      privacy: "aggregate_only_no_mailbox_identity_or_content",
      local: { schemaVersion: 1 },
      providerContracts: expect.arrayContaining([expect.objectContaining({ provider: "gmail" })]),
    });
    const serialized = JSON.stringify(body);
    for (const forbidden of ["subject", "fromAddress", "messageId", "accountId", "providerNativeId", "exception", "token", "body"]) {
      expect(serialized).not.toContain(`\"${forbidden}\"`);
    }
  });
});
