import { afterEach, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createLocalDesktopServer } from "../../server/src/api/localDesktopServer.js";
import { LocalSecurityManager } from "../../server/src/api/localSecurity.js";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
  );
});

async function openDashboard() {
  const app = createLocalDesktopServer({
    security: new LocalSecurityManager(),
    developmentEntitlementsEnabled: true,
  });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));

  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;
  const response = await fetch(baseUrl);
  const html = await response.text();
  const cookie = response.headers.get("set-cookie")?.split(";", 1)[0] ?? "";
  const csrf = html.match(/<meta name="email-shield-csrf" content="([^"]+)"/)?.[1] ?? "";

  expect(response.status).toBe(200);
  expect(cookie).toMatch(/^email_shield_local_session=/);
  expect(csrf.length).toBeGreaterThanOrEqual(32);

  return { baseUrl, cookie, csrf, referrerPolicy: response.headers.get("referrer-policy") };
}

async function mutationNonce(context: { baseUrl: string; cookie: string; csrf: string }): Promise<string> {
  const response = await fetch(`${context.baseUrl}/api/security/mutation-token`, {
    method: "POST",
    headers: {
      Cookie: context.cookie,
      Origin: context.baseUrl,
      Referer: `${context.baseUrl}/`,
      "X-Email-Shield-CSRF": context.csrf,
    },
  });
  const body = await response.json();
  expect(response.status).toBe(200);
  return body.nonce;
}

async function connectFixture(context: { baseUrl: string; cookie: string; csrf: string }): Promise<string> {
  const response = await fetch(`${context.baseUrl}/api/accounts/connect`, {
    method: "POST",
    headers: {
      Cookie: context.cookie,
      Origin: context.baseUrl,
      Referer: `${context.baseUrl}/`,
      "X-Email-Shield-CSRF": context.csrf,
      "X-Email-Shield-Nonce": await mutationNonce(context),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      provider: "gmail",
      mode: "fixture",
      label: "event-source-regression",
    }),
  });
  const body = await response.json();
  expect(response.status).toBe(200);
  expect(body.accountId).toBeTypeOf("string");
  return body.accountId;
}

async function readInitialEvent(response: Response): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) throw new Error("The scan response did not expose a readable event stream.");

  const decoder = new TextDecoder();
  let output = "";
  const deadline = Date.now() + 3_000;
  try {
    while (!output.includes("event: scan-started") && Date.now() < deadline) {
      const remaining = Math.max(1, deadline - Date.now());
      const chunk = await Promise.race([
        reader.read(),
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error("Timed out waiting for scan-started.")), remaining)),
      ]);
      if (chunk.done) break;
      output += decoder.decode(chunk.value, { stream: true });
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  return output;
}

describe("browser EventSource scan handshake", () => {
  it("allows the dashboard to supply same-origin Referer proof without an Origin or CSRF header", async () => {
    const context = await openDashboard();
    expect(context.referrerPolicy).toBe("same-origin");
    const accountId = await connectFixture(context);

    const response = await fetch(`${context.baseUrl}/api/accounts/${encodeURIComponent(accountId)}/scan/quick`, {
      headers: {
        Cookie: context.cookie,
        Referer: `${context.baseUrl}/`,
        Accept: "text/event-stream",
      },
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    const initial = await readInitialEvent(response);
    expect(initial).toContain("event: scan-started");
    expect(initial).toContain('"type":"quick"');
  });
});
