import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DefaultGoogleOAuthRuntime,
  GOOGLE_GMAIL_MODIFY_SCOPE,
} from "../../server/src/oauth/googleOAuthFlow.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Google installed-app OAuth public client", () => {
  it("exchanges a PKCE authorization code without requiring or sending client_secret", async () => {
    let submitted = "";
    vi.stubGlobal("fetch", vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      submitted = String(init?.body ?? "");
      return new Response(JSON.stringify({
        refresh_token: "refresh-token",
        id_token: "id-token",
        scope: `openid email ${GOOGLE_GMAIL_MODIFY_SCOPE}`,
      }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }));

    const result = await new DefaultGoogleOAuthRuntime().exchangeAuthorizationCode({
      clientId: "desktop.apps.googleusercontent.com",
      code: "authorization-code",
      codeVerifier: "v".repeat(64),
      redirectUri: "http://127.0.0.1:49152",
    });

    expect(result.refreshToken).toBe("refresh-token");
    const body = new URLSearchParams(submitted);
    expect(body.get("client_id")).toBe("desktop.apps.googleusercontent.com");
    expect(body.get("code_verifier")).toBe("v".repeat(64));
    expect(body.has("client_secret")).toBe(false);
  });

  it("still sends an optional Google client credential when a specific installed client registration provides one", async () => {
    let submitted = "";
    vi.stubGlobal("fetch", vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      submitted = String(init?.body ?? "");
      return new Response(JSON.stringify({
        refresh_token: "refresh-token",
        id_token: "id-token",
        scope: `openid email ${GOOGLE_GMAIL_MODIFY_SCOPE}`,
      }), { status: 200 });
    }));

    await new DefaultGoogleOAuthRuntime().exchangeAuthorizationCode({
      clientId: "desktop.apps.googleusercontent.com",
      clientSecret: "optional-installed-client-value",
      code: "authorization-code",
      codeVerifier: "v".repeat(64),
      redirectUri: "http://127.0.0.1:49152",
    });
    expect(new URLSearchParams(submitted).get("client_secret")).toBe("optional-installed-client-value");
  });
});
