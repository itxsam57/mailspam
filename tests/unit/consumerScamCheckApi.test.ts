import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { createConsumerDesktopServer } from "../../server/src/api/consumerDesktopServer.js";
import { LocalSecurityManager } from "../../server/src/api/localSecurity.js";
import { CommunityNetwork } from "../../server/src/community/network.js";

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

async function start(): Promise<BrowserContext> {
  const dataDirectory = mkdtempSync(join(tmpdir(), "email-shield-scam-check-api-"));
  roots.push(dataDirectory);
  const app = createConsumerDesktopServer({
    security: new LocalSecurityManager(),
    community: new CommunityNetwork({ dataDirectory }),
  });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", () => resolve()));
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

function headers(context: BrowserContext, extra: Record<string, string> = {}): Record<string, string> {
  return {
    Cookie: context.cookie,
    Origin: context.baseUrl,
    Referer: `${context.baseUrl}/`,
    "X-Email-Shield-CSRF": context.csrf,
    ...extra,
  };
}

describe("consumer Scam Check local API", () => {
  it("requires the protected local session and same-origin proof", async () => {
    const context = await start();
    expect((await fetch(`${context.baseUrl}/api/scam-check/v1/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ schemaVersion: 1, kind: "message", text: "hello" }),
    })).status).toBe(401);

    expect((await fetch(`${context.baseUrl}/api/scam-check/v1/analyze`, {
      method: "POST",
      headers: {
        Cookie: context.cookie,
        "X-Email-Shield-CSRF": context.csrf,
        Origin: "http://127.0.0.1:65531",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ schemaVersion: 1, kind: "message", text: "hello" }),
    })).status).toBe(403);
  });

  it("uses its scoped JSON parser without raising the rest of the desktop API limit", async () => {
    const context = await start();
    const text = `Meeting reminder ${"a".repeat(80 * 1024)}`;
    const response = await fetch(`${context.baseUrl}/api/scam-check/v1/analyze`, {
      method: "POST",
      headers: headers(context, { "Content-Type": "application/json" }),
      body: JSON.stringify({ schemaVersion: 1, kind: "message", text }),
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toContain("no-store");
    const body = await response.json();
    expect(body).toMatchObject({ schemaVersion: 1, confirmedByRule: false });
  });

  it("returns bounded generic parser errors instead of leaking submitted content", async () => {
    const context = await start();
    const response = await fetch(`${context.baseUrl}/api/scam-check/v1/analyze`, {
      method: "POST",
      headers: headers(context, { "Content-Type": "application/json" }),
      body: `{"secret":"DO_NOT_ECHO","padding":"${"x".repeat(1024 * 1024)}"}`,
    });
    expect(response.status).toBe(413);
    const body = await response.text();
    expect(body).toContain("resource limit");
    expect(body).not.toContain("DO_NOT_ECHO");
  });

  it("accepts EML through a dedicated raw parser and keeps authentication untrusted", async () => {
    const context = await start();
    const message = Buffer.from([
      "From: Billing <billing@example.net>",
      "To: owner@example.com",
      "Subject: Subscription renewed",
      "Authentication-Results: attacker.example; spf=pass; dkim=pass; dmarc=pass",
      "Content-Type: text/plain; charset=utf-8",
      "",
      "Your subscription renewed. Call now at (555) 123-4567.",
      "",
    ].join("\r\n"), "utf8");
    const response = await fetch(`${context.baseUrl}/api/scam-check/v1/eml`, {
      method: "POST",
      headers: headers(context, { "Content-Type": "message/rfc822" }),
      body: message,
    });
    expect(response.status).toBe(200);
    const body = await response.json();
    const transport = body.layerResults.find((layer: { layer: string }) => layer.layer === "transport_auth");
    expect(transport.incomplete).toBe(true);
    expect(body.evidence.some((item: { code: string }) => item.code === "CALLBACK_SCAM_INTENT")).toBe(true);
  });

  it("rejects unsupported images locally instead of invoking an implicit cloud fallback", async () => {
    const context = await start();
    const response = await fetch(`${context.baseUrl}/api/scam-check/v1/image`, {
      method: "POST",
      headers: headers(context, { "Content-Type": "image/gif" }),
      body: Buffer.from("GIF89a", "ascii"),
    });
    expect(response.status).toBe(415);
    expect((await response.json()).error).toMatch(/not supported/i);
  });
});
