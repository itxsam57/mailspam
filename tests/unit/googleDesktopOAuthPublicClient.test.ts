import { afterEach, describe, expect, it, vi } from "vitest";
import {
  DefaultGoogleOAuthRuntime,
  GOOGLE_GMAIL_MODIFY_SCOPE,
} from "../../server/src/oauth/googleOAuthFlow.js";

afterEach(() => {
  delete process.env.EMAIL_SHIELD_GOOGLE_CLIENT_SECRET;
  vi.unstubAllGlobals();
});

describe("Google desktop OAuth token exchange", () => {
  it("fails closed before network exchange when the matching client secret is absent", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);

    await expect(new DefaultGoogleOAuthRuntime().exchangeAuthorizationCode({
      clientId: "desktop.apps.googleusercontent.com",
      code: "authorization-code",
      codeVerifier: "v".repeat(64),
      redirectUri: "http://127.0.0.1:49152",
    })).rejects.toThrow("Google OAuth client secret is not configured");

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("sends the matching client ID and client secret with PKCE to the token endpoint", async () => {
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
      clientSecret: "matching-desktop-client-secret",
      code: "authorization-code",
      codeVerifier: "v".repeat(64),
      redirectUri: "http://127.0.0.1:49152",
    });

    const body = new URLSearchParams(submitted);
    expect(body.get("client_id")).toBe("desktop.apps.googleusercontent.com");
    expect(body.get("client_secret")).toBe("matching-desktop-client-secret");
    expect(body.get("code")).toBe("authorization-code");
    expect(body.get("code_verifier")).toBe("v".repeat(64));
    expect(body.get("grant_type")).toBe("authorization_code");
    expect(body.get("redirect_uri")).toBe("http://127.0.0.1:49152");
  });
});
