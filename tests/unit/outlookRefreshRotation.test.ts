import { afterEach, describe, expect, it, vi } from "vitest";
import { OutlookAdapter } from "../../server/src/adapters/outlook/outlookAdapter.js";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Outlook rotating refresh-token lifecycle", () => {
  it("persists Microsoft's replacement token only after the Graph account identity matches", async () => {
    const rotationSink = vi.fn(async () => {});
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes("/oauth2/v2.0/token")) {
        const form = init?.body as URLSearchParams;
        expect(form.get("grant_type")).toBe("refresh_token");
        expect(form.get("refresh_token")).toBe("refresh-one");
        expect(form.get("client_id")).toBe("public-client-id");
        expect(form.has("client_secret")).toBe(false);
        return jsonResponse({
          access_token: "access-token-private",
          refresh_token: "refresh-two",
          scope: "offline_access User.Read Mail.ReadWrite",
        });
      }
      if (url.endsWith("/me?$select=id,mail,userPrincipalName")) {
        expect(new Headers(init?.headers).get("Authorization")).toBe("Bearer access-token-private");
        return jsonResponse({ id: "stable-graph-account-id", mail: "person@example.com" });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const adapter = new OutlookAdapter({
      clientId: "public-client-id",
      refreshToken: "refresh-one",
      accountId: "stable-graph-account-id",
    }, rotationSink);
    await adapter.connect(new AbortController().signal);

    expect(rotationSink).toHaveBeenCalledTimes(1);
    expect(rotationSink).toHaveBeenCalledWith("refresh-two");
    await adapter.disconnect();
  });

  it("does not persist a replacement token when the refreshed credential resolves to another Microsoft account", async () => {
    const rotationSink = vi.fn(async () => {});
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/oauth2/v2.0/token")) {
        return jsonResponse({
          access_token: "access-token-private",
          refresh_token: "refresh-two",
          scope: "offline_access User.Read Mail.ReadWrite",
        });
      }
      if (url.endsWith("/me?$select=id,mail,userPrincipalName")) {
        return jsonResponse({ id: "different-account-id", mail: "other@example.com" });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const adapter = new OutlookAdapter({
      clientId: "public-client-id",
      refreshToken: "refresh-one",
      accountId: "expected-account-id",
    }, rotationSink);

    await expect(adapter.connect(new AbortController().signal)).rejects.toThrow(/different Microsoft account/i);
    expect(rotationSink).not.toHaveBeenCalled();
  });

  it("fails provider connect if secure persistence of the replacement token fails", async () => {
    const rotationSink = vi.fn(async () => { throw new Error("vault write failed"); });
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/oauth2/v2.0/token")) {
        return jsonResponse({
          access_token: "access-token-private",
          refresh_token: "refresh-two",
          scope: "offline_access User.Read Mail.ReadWrite",
        });
      }
      if (url.endsWith("/me?$select=id,mail,userPrincipalName")) {
        return jsonResponse({ id: "stable-id", mail: "person@example.com" });
      }
      throw new Error(`Unexpected fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);

    const adapter = new OutlookAdapter({
      clientId: "public-client-id",
      refreshToken: "refresh-one",
      accountId: "stable-id",
    }, rotationSink);

    await expect(adapter.connect(new AbortController().signal)).rejects.toThrow(/vault write failed/i);
    expect(rotationSink).toHaveBeenCalledTimes(1);
  });
});
