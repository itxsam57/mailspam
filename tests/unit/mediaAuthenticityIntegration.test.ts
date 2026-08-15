import { readFileSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { createConsumerDesktopServer } from "../../server/src/api/consumerDesktopServer.js";
import { LocalSecurityManager } from "../../server/src/api/localSecurity.js";
import type { MediaAuthenticityPort } from "../../server/src/consumer/mediaAuthenticity.js";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

async function startDesktop(detector?: MediaAuthenticityPort) {
  const security = new LocalSecurityManager();
  const app = createConsumerDesktopServer({ security, mediaAuthenticityDetector: detector });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const home = await fetch(baseUrl);
  const html = await home.text();
  const cookie = home.headers.get("set-cookie")?.split(";", 1)[0] ?? "";
  const csrf = html.match(/<meta name="email-shield-csrf" content="([^"]+)"/)?.[1] ?? "";
  if (!cookie || !csrf) throw new Error("Desktop security session did not initialize for Media Authenticity test.");
  return { baseUrl, cookie, csrf, html };
}

function protectedHeaders(session: Awaited<ReturnType<typeof startDesktop>>): Record<string, string> {
  return {
    Cookie: session.cookie,
    Origin: session.baseUrl,
    Referer: `${session.baseUrl}/`,
    "X-Email-Shield-CSRF": session.csrf,
  };
}

async function mutationNonce(session: Awaited<ReturnType<typeof startDesktop>>): Promise<string> {
  const response = await fetch(`${session.baseUrl}/api/security/mutation-token`, {
    method: "POST",
    headers: protectedHeaders(session),
  });
  const body = await response.json() as { nonce?: string; error?: string };
  if (!response.ok || !body.nonce) throw new Error(body.error ?? "Could not obtain mutation nonce.");
  return body.nonce;
}

function requestBody(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

async function postMedia(
  session: Awaited<ReturnType<typeof startDesktop>>,
  bytes: Uint8Array,
  kind = "image",
  mime = "image/png",
): Promise<Response> {
  const nonce = await mutationNonce(session);
  return fetch(`${session.baseUrl}/api/consumer/v1/media/authenticity`, {
    method: "POST",
    headers: {
      ...protectedHeaders(session),
      "Content-Type": "application/octet-stream",
      "X-Email-Shield-Media-Kind": kind,
      "X-Email-Shield-Media-Mime": mime,
      "X-Email-Shield-Nonce": nonce,
    },
    body: requestBody(bytes),
  });
}

describe("Media Authenticity capability-gated integration", () => {
  it("renders the consumer tool but truthfully disables capability when no vetted detector is configured", async () => {
    const session = await startDesktop();
    expect(session.html).toContain('<script defer src="/media-authenticity.js"></script>');

    const source = readFileSync(new URL("../../web/media-authenticity.js", import.meta.url), "utf8");
    expect(source).toContain("Media Authenticity");
    expect(source).toContain("consumerCheckMediaAuthenticity");
    expect(source).toContain("/api/consumer/v1/media/authenticity/status");
    expect(source).toContain("This is not proof that the media is authentic");
    expect(source).not.toContain("localStorage");
    expect(source).not.toContain("sessionStorage");

    const status = await fetch(`${session.baseUrl}/api/consumer/v1/media/authenticity/status`, {
      headers: protectedHeaders(session),
    });
    expect(status.status).toBe(200);
    expect(status.headers.get("cache-control")).toContain("no-store");
    const body = await status.json() as Record<string, unknown>;
    expect(body.available).toBe(false);
    expect(body.implementationStatus).toBe("detector_not_configured");
    expect(String(body.limitation)).toMatch(/will not fabricate a deepfake verdict/i);
  });

  it("never converts an unconfigured detector into an authentic/no-indicator result after real byte submission", async () => {
    const session = await startDesktop();
    const response = await postMedia(
      session,
      Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    );
    expect(response.status).toBe(200);
    const body = await response.json() as Record<string, unknown>;
    expect(body.state).toBe("unavailable");
    expect(body.confidenceBand).toBeNull();
    expect(String((body.reasons as string[])[0])).toMatch(/will not fabricate a deepfake verdict/i);
  });

  it("passes the exact explicitly selected bounded bytes to a configured detector and returns its evidence without relabeling it as proof", async () => {
    let observed: { bytes: number[]; sha256: string; mimeType: string; kind: string } | null = null;
    const detector: MediaAuthenticityPort = {
      async analyze(input) {
        observed = {
          bytes: [...input.bytes],
          sha256: input.sha256,
          mimeType: input.mimeType,
          kind: input.kind,
        };
        return {
          state: "likely_manipulated",
          confidenceBand: "strong",
          reasons: ["Configured test detector observed a deterministic certification marker."],
          detector: "vetted-test-detector",
        };
      },
    };
    const session = await startDesktop(detector);

    const status = await fetch(`${session.baseUrl}/api/consumer/v1/media/authenticity/status`, {
      headers: protectedHeaders(session),
    });
    expect(await status.json()).toMatchObject({
      available: true,
      implementationStatus: "vetted_detector_configured",
      privacy: "explicit_user_selected_media_only",
    });

    const bytes = Uint8Array.from([1, 2, 3, 4, 5, 6]);
    const response = await postMedia(session, bytes);
    expect(response.status).toBe(200);
    const body = await response.json() as Record<string, unknown>;
    expect(body).toMatchObject({
      state: "likely_manipulated",
      confidenceBand: "strong",
      detector: "vetted-test-detector",
      privacy: "explicit_user_submitted_media",
    });
    expect(observed).not.toBeNull();
    expect(observed!.bytes).toEqual([...bytes]);
    expect(observed!.sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(observed!.mimeType).toBe("image/png");
    expect(observed!.kind).toBe("image");
  });

  it("rejects media mutation without a one-use local authorization nonce", async () => {
    const session = await startDesktop();
    const response = await fetch(`${session.baseUrl}/api/consumer/v1/media/authenticity`, {
      method: "POST",
      headers: {
        ...protectedHeaders(session),
        "Content-Type": "application/octet-stream",
        "X-Email-Shield-Media-Kind": "image",
        "X-Email-Shield-Media-Mime": "image/png",
      },
      body: requestBody(Uint8Array.from([1, 2, 3])),
    });
    expect(response.status).toBe(409);
  });
});
