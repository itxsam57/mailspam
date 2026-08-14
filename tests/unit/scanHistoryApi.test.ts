import { afterEach, describe, expect, it } from "vitest";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createLocalDesktopServer } from "../../server/src/api/localDesktopServer.js";
import { LocalSecurityManager } from "../../server/src/api/localSecurity.js";
import { defaultScanStateRepository } from "../../server/src/api/defaultScanStateRepository.js";
import { sessionStore } from "../../server/src/api/sessionStore.js";
import type { ScanHistoryRecord } from "../../server/src/api/scanStatePersistence.js";

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

async function start(): Promise<BrowserContext> {
  const app = createLocalDesktopServer({ security: new LocalSecurityManager(), developmentEntitlementsEnabled: true });
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

function resumableRecord(): ScanHistoryRecord {
  return {
    scanId: "123e4567-e89b-42d3-a456-426614174111",
    type: "quick",
    status: "interrupted",
    startedAt: Date.now() - 5_000,
    updatedAt: Date.now() - 1_000,
    completedAt: null,
    counters: {
      examined: 1,
      safe: 1,
      review: 0,
      highRisk: 0,
      confirmedThreat: 0,
      unknown: 0,
      skipped: 0,
      malformed: 0,
    },
    checkpoint: {
      currentCursor: "1",
      folderCursors: {},
      completedFolders: [],
      seenSenderHashes: ["a".repeat(64)],
      seenMessageHashes: [],
    },
  };
}

describe("protected scan history API", () => {
  it("returns privacy-reduced history and resolves resume by opaque scan ID without serializing checkpoints", async () => {
    const context = await start();
    const connected = await mutate(context, "/api/accounts/connect", {
      provider: "gmail",
      mode: "fixture",
      label: "scan-history-test",
    });
    expect(connected.status).toBe(200);
    const accountId = (await connected.json()).accountId as string;
    accountIds.push(accountId);
    const session = sessionStore.get(accountId);
    expect(session).toBeDefined();

    const record = resumableRecord();
    defaultScanStateRepository.save(session!.policyAccountKey, record);

    const unauthenticated = await fetch(`${context.baseUrl}/api/accounts/${accountId}/scan-history`, {
      headers: { Cookie: context.cookie, Origin: context.baseUrl, Referer: `${context.baseUrl}/` },
    });
    expect(unauthenticated.status).toBe(403);

    const historyResponse = await fetch(`${context.baseUrl}/api/accounts/${accountId}/scan-history`, {
      headers: headers(context),
    });
    expect(historyResponse.status).toBe(200);
    const historyText = await historyResponse.text();
    expect(historyText).not.toContain('"checkpoint"');
    expect(historyText).not.toContain('"currentCursor"');
    expect(historyText).not.toContain('"folderCursors"');
    expect(historyText).not.toContain('"seenSenderHashes"');
    expect(historyText).not.toContain('"seenMessageHashes"');
    const historyBody = JSON.parse(historyText);
    expect(historyBody.history[0]).toMatchObject({
      scanId: record.scanId,
      type: "quick",
      status: "interrupted",
      resumable: true,
      counters: { examined: 1 },
    });

    // Source-level Vitest imports server/src directly, while the Worker entry is
    // intentionally compiled JavaScript under server/dist. The API still proves
    // that Resume exposes only the already-public counters needed to preserve UI
    // continuity; provider cursors/hashes remain server-only.
    const resumeResponse = await fetch(`${context.baseUrl}/api/accounts/${accountId}/scan/resume/${record.scanId}`, {
      headers: {
        Cookie: context.cookie,
        Origin: context.baseUrl,
        Referer: `${context.baseUrl}/`,
        Accept: "text/event-stream",
      },
    });
    expect(resumeResponse.status).toBe(200);
    const stream = await resumeResponse.text();
    expect(stream).toContain("event: scan-started");
    expect(stream).toContain('"resumed":true');
    expect(stream).toContain('"counters":{"examined":1');
    expect(stream).toContain("event: scan-error");
    expect(stream).not.toContain('"checkpoint"');
    expect(stream).not.toContain('"currentCursor"');
    expect(stream).not.toContain('"folderCursors"');
    expect(stream).not.toContain('"seenSenderHashes"');
    expect(stream).not.toContain('"seenMessageHashes"');
    expect(stream).not.toContain('"1"');

    const retained = defaultScanStateRepository.get(session!.policyAccountKey, record.scanId);
    expect(retained?.status).toBe("failed");
    expect(retained?.checkpoint?.currentCursor).toBe("1");
    expect(retained?.counters.examined).toBe(1);
  });

  it("rejects resume requests that do not belong to the selected account", async () => {
    const context = await start();
    const connected = await mutate(context, "/api/accounts/connect", {
      provider: "outlook",
      mode: "fixture",
      label: "scan-history-isolation",
    });
    expect(connected.status).toBe(200);
    const accountId = (await connected.json()).accountId as string;
    accountIds.push(accountId);

    const response = await fetch(`${context.baseUrl}/api/accounts/${accountId}/scan/resume/123e4567-e89b-42d3-a456-426614174999`, {
      headers: {
        Cookie: context.cookie,
        Origin: context.baseUrl,
        Referer: `${context.baseUrl}/`,
        Accept: "text/event-stream",
      },
    });
    expect(response.status).toBe(404);
  });
});