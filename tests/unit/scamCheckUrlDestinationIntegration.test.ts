import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createConsumerDesktopServer } from "../../server/src/api/consumerDesktopServer.js";
import { LocalSecurityManager } from "../../server/src/api/localSecurity.js";
import { createDestinationAnalysisCoordinator } from "../../server/src/workflows/analyzeLinks.js";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

async function startDesktop(fetchImpl: (url: string) => Promise<{ finalUrl: string; contentType: string; body: string } | null>) {
  const security = new LocalSecurityManager();
  const destinationAnalyzer = createDestinationAnalysisCoordinator({
    fetchImpl,
    networkEnabled: true,
    cacheKey: Buffer.alloc(32, 7),
  });
  const app = createConsumerDesktopServer({ security, destinationAnalyzer });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const home = await fetch(baseUrl);
  const html = await home.text();
  const cookie = home.headers.get("set-cookie")?.split(";", 1)[0] ?? "";
  const csrf = html.match(/<meta name="email-shield-csrf" content="([^"]+)"/)?.[1] ?? "";
  if (!cookie || !csrf) throw new Error("Desktop security session did not initialize for Scam Check URL test.");
  return { baseUrl, cookie, csrf };
}

async function scamCheck(
  session: Awaited<ReturnType<typeof startDesktop>>,
  body: unknown,
): Promise<Response> {
  return fetch(`${session.baseUrl}/api/scam-check/v1/analyze`, {
    method: "POST",
    headers: {
      Cookie: session.cookie,
      Origin: session.baseUrl,
      Referer: `${session.baseUrl}/`,
      "Content-Type": "application/json",
      "X-Email-Shield-CSRF": session.csrf,
    },
    body: JSON.stringify(body),
  });
}

describe("Scam Check explicit URL destination integration", () => {
  it("runs Link mode through the shared explicit destination analyzer", async () => {
    const fetchImpl = vi.fn(async (url: string) => ({
      finalUrl: url,
      contentType: "text/html",
      body: "<html><body>Ordinary public page.</body></html>",
    }));
    const session = await startDesktop(fetchImpl);
    const response = await scamCheck(session, {
      schemaVersion: 1,
      kind: "url",
      url: "https://example.com",
    });

    expect(response.status).toBe(200);
    const body = await response.json() as {
      destinationAnalysis?: {
        results: Array<{ url: string; classification: string }>;
        escalatedToHighRisk: boolean;
      };
    };
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(fetchImpl).toHaveBeenCalledWith("https://example.com/");
    expect(body.destinationAnalysis?.results).toEqual([
      expect.objectContaining({ url: "https://example.com/", classification: "benign" }),
    ]);
    expect(body.destinationAnalysis?.escalatedToHighRisk).toBe(false);
  });

  it("uses the shared encoded-URL canonicalizer before explicit destination analysis", async () => {
    const fetchImpl = vi.fn(async (url: string) => ({
      finalUrl: url,
      contentType: "text/plain",
      body: "ordinary text",
    }));
    const session = await startDesktop(fetchImpl);
    const response = await scamCheck(session, {
      schemaVersion: 1,
      kind: "url",
      url: "https%3A%2F%2Fexample.com%2Faccount",
    });

    expect(response.status).toBe(200);
    expect(fetchImpl).toHaveBeenCalledWith("https://example.com/account");
  });

  it("does not add destination network inspection to pasted-message mode", async () => {
    const fetchImpl = vi.fn(async (url: string) => ({
      finalUrl: url,
      contentType: "text/html",
      body: "unused",
    }));
    const session = await startDesktop(fetchImpl);
    const response = await scamCheck(session, {
      schemaVersion: 1,
      kind: "message",
      text: "Meeting moved to Tuesday. No action is required.",
    });

    expect(response.status).toBe(200);
    expect(fetchImpl).not.toHaveBeenCalled();
    const body = await response.json() as { destinationAnalysis?: unknown };
    expect(body.destinationAnalysis).toBeUndefined();
  });
});
