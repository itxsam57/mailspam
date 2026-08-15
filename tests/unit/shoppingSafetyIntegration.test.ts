import { readFileSync } from "node:fs";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { createConsumerDesktopServer } from "../../server/src/api/consumerDesktopServer.js";
import { LocalSecurityManager } from "../../server/src/api/localSecurity.js";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

async function startDesktop() {
  const security = new LocalSecurityManager();
  const app = createConsumerDesktopServer({ security });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const home = await fetch(baseUrl);
  const html = await home.text();
  const cookie = home.headers.get("set-cookie")?.split(";", 1)[0] ?? "";
  const csrf = html.match(/<meta name="email-shield-csrf" content="([^"]+)"/)?.[1] ?? "";
  if (!cookie || !csrf) throw new Error("Desktop security session did not initialize for Shopping Safety test.");
  return { baseUrl, cookie, csrf, html };
}

async function mutationNonce(baseUrl: string, cookie: string, csrf: string): Promise<string> {
  const response = await fetch(`${baseUrl}/api/security/mutation-token`, {
    method: "POST",
    headers: {
      Cookie: cookie,
      Origin: baseUrl,
      Referer: `${baseUrl}/`,
      "X-Email-Shield-CSRF": csrf,
    },
  });
  const body = await response.json() as { nonce?: string; error?: string };
  if (!response.ok || !body.nonce) throw new Error(body.error ?? "Could not obtain mutation nonce.");
  return body.nonce;
}

async function protectedPost(
  session: Awaited<ReturnType<typeof startDesktop>>,
  path: string,
  body: unknown,
): Promise<Response> {
  const nonce = await mutationNonce(session.baseUrl, session.cookie, session.csrf);
  return fetch(`${session.baseUrl}${path}`, {
    method: "POST",
    headers: {
      Cookie: session.cookie,
      Origin: session.baseUrl,
      Referer: `${session.baseUrl}/`,
      "Content-Type": "application/json",
      "X-Email-Shield-CSRF": session.csrf,
      "X-Email-Shield-Nonce": nonce,
    },
    body: JSON.stringify(body),
  });
}

describe("Shopping Safety end-to-end consumer integration", () => {
  it("composes a real consumer control and posts only explicit storefront input to the protected route", async () => {
    const session = await startDesktop();
    expect(session.html).toContain('<script defer src="/shopping-safety.js"></script>');

    const browserSource = readFileSync(new URL("../../web/shopping-safety.js", import.meta.url), "utf8");
    expect(browserSource).toContain("Shopping Safety");
    expect(browserSource).toContain("consumerCheckShopping");
    expect(browserSource).toContain("/api/consumer/v1/shopping/check");
    expect(browserSource).toContain("Check purchase");
    expect(browserSource).toContain("does not inspect browser history");
    expect(browserSource).not.toContain("localStorage");
    expect(browserSource).not.toContain("sessionStorage");
  });

  it("turns irreversible payment plus urgency/off-platform handling into High Risk through the real protected API", async () => {
    const session = await startDesktop();
    const response = await protectedPost(session, "/api/consumer/v1/shopping/check", {
      schemaVersion: 1,
      url: "https://shop.example.test/deal",
      sellerName: "Example Shop",
      advertisedPriceText: "$99",
      pageText: "Only today. Contact us on WhatsApp to complete the order.",
      paymentText: "Pay by bank transfer now",
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toContain("no-store");
    const body = await response.json() as {
      verdict: string;
      signals: Array<{ code: string }>;
      privacy: string;
      limitations: string[];
    };
    expect(body.verdict).toBe("high_risk");
    expect(body.signals.map((signal) => signal.code)).toEqual(expect.arrayContaining([
      "SHOPPING_IRREVERSIBLE_PAYMENT",
      "SHOPPING_URGENCY_PRESSURE",
      "SHOPPING_OFF_PLATFORM_PAYMENT_CONTACT",
    ]));
    expect(body.privacy).toBe("explicit_storefront_input_only");
    expect(body.limitations.join(" ")).toMatch(/does not invent merchant age/i);
  });

  it("rejects browser-history injection, embedded URL credentials and oversized storefront text at the public route", async () => {
    const session = await startDesktop();

    const injected = await protectedPost(session, "/api/consumer/v1/shopping/check", {
      schemaVersion: 1,
      url: "https://shop.example.test/",
      history: ["https://private.example.test/"],
    });
    expect(injected.status).toBe(400);

    const credentialed = await protectedPost(session, "/api/consumer/v1/shopping/check", {
      schemaVersion: 1,
      url: "https://user:secret@shop.example.test/",
    });
    expect(credentialed.status).toBe(400);

    const oversized = await protectedPost(session, "/api/consumer/v1/shopping/check", {
      schemaVersion: 1,
      url: "https://shop.example.test/",
      pageText: "x".repeat(32_001),
    });
    expect(oversized.status).toBe(400);
  });
});
