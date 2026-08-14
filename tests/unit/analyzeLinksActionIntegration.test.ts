import { afterEach, describe, expect, it, vi } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createConsumerDesktopServer } from "../../server/src/api/consumerDesktopServer.js";
import { LocalSecurityManager } from "../../server/src/api/localSecurity.js";
import { sessionStore } from "../../server/src/api/sessionStore.js";
import { createDestinationAnalysisCoordinator } from "../../server/src/workflows/analyzeLinks.js";

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
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

async function start() {
  const fetchImpl = vi.fn(async (url: string) => ({
    finalUrl: url,
    contentType: "text/html",
    body: "<html><form><input type=password name=secret></form></html>",
  }));
  const coordinator = createDestinationAnalysisCoordinator({
    fetchImpl,
    cacheKey: Buffer.alloc(32, 47),
  });
  const app = createConsumerDesktopServer({
    security: new LocalSecurityManager(),
    destinationAnalyzer: coordinator,
    developmentEntitlementsEnabled: true,
  });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const home = await fetch(baseUrl);
  const html = await home.text();
  const context = {
    baseUrl,
    cookie: home.headers.get("set-cookie")?.split(";", 1)[0] ?? "",
    csrf: html.match(/<meta name="email-shield-csrf" content="([^"]+)"/)?.[1] ?? "",
  };
  expect(home.status).toBe(200);
  return { context, fetchImpl };
}

function headers(context: BrowserContext, extra: Record<string, string> = {}) {
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
    headers: headers(context),
  });
  expect(response.status).toBe(200);
  return (await response.json()).nonce as string;
}

async function mutate(context: BrowserContext, path: string, body: unknown): Promise<Response> {
  return fetch(`${context.baseUrl}${path}`, {
    method: "POST",
    headers: headers(context, {
      "Content-Type": "application/json",
      "X-Email-Shield-Nonce": await nonce(context),
    }),
    body: JSON.stringify(body),
  });
}

async function connectFixture(context: BrowserContext, provider: "gmail" | "outlook"): Promise<string> {
  const response = await mutate(context, "/api/accounts/connect", {
    provider,
    mode: "fixture",
    label: `analyze-links-${provider}`,
  });
  expect(response.status).toBe(200);
  const accountId = (await response.json()).accountId as string;
  accountIds.push(accountId);
  return accountId;
}

function scanCards(stream: string): any[] {
  const cards: any[] = [];
  for (const line of stream.split(/\r?\n/)) {
    if (!line.startsWith("data: ")) continue;
    try {
      const value = JSON.parse(line.slice(6));
      if (Array.isArray(value?.suspiciousCards)) cards.push(...value.suspiciousCards);
    } catch {}
  }
  return cards;
}

describe("Analyze Links scanned-message action", () => {
  it("binds a real scan capability to server-owned destinations and rejects browser/cross-account substitution", async () => {
    const { context, fetchImpl } = await start();
    const firstAccount = await connectFixture(context, "gmail");
    const secondAccount = await connectFixture(context, "outlook");

    const scanResponse = await fetch(`${context.baseUrl}/api/accounts/${encodeURIComponent(firstAccount)}/scan/full`, {
      headers: headers(context, { Accept: "text/event-stream" }),
    });
    expect(scanResponse.status).toBe(200);
    const stream = await scanResponse.text();
    const cards = scanCards(stream);
    const analyzable = cards.find((card) => card?.reviewAction?.canAnalyzeLinks === true && card?.reviewAction?.token);
    expect(analyzable).toBeDefined();
    expect(analyzable.envelope).toEqual(expect.objectContaining({
      subject: expect.any(String),
      from: expect.any(Object),
    }));
    expect(analyzable.envelope).not.toHaveProperty("links");
    expect(analyzable.envelope).not.toHaveProperty("textPreview");
    expect(analyzable.envelope).not.toHaveProperty("attachments");

    const token = analyzable.reviewAction.token as string;
    const injectedUrl = "https://attacker-injected.example.test/credential-steal";
    const injected = await mutate(context, `/api/accounts/${firstAccount}/messages/analyze-links`, {
      token,
      envelope: { links: [{ normalizedUrl: injectedUrl }] },
    });
    expect(injected.status).toBe(400);
    expect(fetchImpl).not.toHaveBeenCalled();

    const crossAccount = await mutate(context, `/api/accounts/${secondAccount}/messages/analyze-links`, { token });
    expect(crossAccount.status).toBe(400);
    expect(fetchImpl).not.toHaveBeenCalled();

    const valid = await mutate(context, `/api/accounts/${firstAccount}/messages/analyze-links`, { token });
    expect(valid.status).toBe(200);
    const body = await valid.json();
    expect(body).toMatchObject({
      accountId: firstAccount,
      token,
      escalatedToHighRisk: true,
      analyzedDestinations: expect.any(Number),
      results: expect.any(Array),
    });
    expect(body.analyzedDestinations).toBeGreaterThan(0);
    expect(body.results.some((item: any) => item.classification === "credential_trap")).toBe(true);
    expect(fetchImpl).toHaveBeenCalled();
    const analyzedUrls = fetchImpl.mock.calls.map((call) => call[0]);
    expect(analyzedUrls).not.toContain(injectedUrl);
    expect(analyzedUrls.every((url) => typeof url === "string" && /^https?:\/\//.test(url))).toBe(true);
  });
});
