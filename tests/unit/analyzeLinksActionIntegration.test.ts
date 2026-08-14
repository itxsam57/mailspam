import { afterEach, describe, expect, it, vi } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createConsumerDesktopServer } from "../../server/src/api/consumerDesktopServer.js";
import { LocalSecurityManager } from "../../server/src/api/localSecurity.js";
import { sessionStore } from "../../server/src/api/sessionStore.js";
import type { ScanActionContext } from "../../server/src/workflows/scanWorkflows.js";
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

function scannedActionContext(url: string): ScanActionContext {
  return {
    providerNativeId: "fixture-native-analyze-links",
    messageId: "<fixture-analyze-links@example.test>",
    exceptionKey: `message:${"a".repeat(64)}`,
    senderAddress: "sender@example.test",
    normalizedFolder: "inbox",
    links: [{
      visibleText: "Review account",
      rawUrl: url,
      normalizedUrl: url,
      claimedBrand: null,
      brandDomainMismatch: null,
      source: "body",
    }],
    unsubscribe: { available: false, method: "none", target: null, source: "none", actionKey: null },
    communityReport: {
      campaignFingerprint: "b".repeat(64),
      indicators: [{ type: "campaign", value: "b".repeat(64) }],
      evidenceCodes: ["CERTIFICATION_LINK"],
      evidenceScore: 2,
      verdict: "review",
    },
  };
}

describe("Analyze Links scanned-message action", () => {
  it("binds the opaque review capability to a server-owned canonical destination and rejects browser/cross-account substitution", async () => {
    const { context, fetchImpl } = await start();
    const firstAccount = await connectFixture(context, "gmail");
    const secondAccount = await connectFixture(context, "outlook");
    const firstSession = sessionStore.get(firstAccount);
    expect(firstSession).toBeDefined();

    // Consumer composition installs the Analyze Links bridge onto the same
    // review-token registry used by compiled scanStream. Registering the exact
    // ScanActionContext here isolates capability authorization from the source-
    // Vitest Worker lifecycle; compiled browser smoke certifies the real scan.
    const canonicalUrl = "https://canonical-message.example.test/login";
    const registered = sessionStore.registerReviewAction(firstSession!, scannedActionContext(canonicalUrl));
    expect((registered as any).canAnalyzeLinks).toBe(true);
    const token = registered.token;

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
      analyzedDestinations: 1,
      results: expect.any(Array),
    });
    expect(body.results).toHaveLength(1);
    expect(body.results[0]).toMatchObject({ classification: "credential_trap" });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(fetchImpl).toHaveBeenCalledWith(canonicalUrl, expect.any(AbortSignal));
    expect(fetchImpl).not.toHaveBeenCalledWith(injectedUrl, expect.anything());
  });
});
