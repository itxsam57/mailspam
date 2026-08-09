import { afterEach, describe, expect, it, vi } from "vitest";
import type { AccountSession, SessionStore } from "../../server/src/api/sessionStore.js";
import type { AdapterConfig } from "../../server/src/api/adapterConfig.js";
import {
  DefaultGoogleOAuthRuntime,
  GOOGLE_GMAIL_MODIFY_SCOPE,
  GoogleOAuthFlowManager,
  googleScopeGranted,
  type GoogleOAuthRuntime,
} from "../../server/src/oauth/googleOAuthFlow.js";

const managers: GoogleOAuthFlowManager[] = [];

afterEach(() => {
  for (const manager of managers.splice(0)) manager.close();
  vi.unstubAllGlobals();
});

function callbackParts(authorizationUrl: string): { redirect: string; state: string; nonce: string } {
  const auth = new URL(authorizationUrl);
  return {
    redirect: auth.searchParams.get("redirect_uri")!,
    state: auth.searchParams.get("state")!,
    nonce: auth.searchParams.get("nonce")!,
  };
}

function fakeSessionStore(createSecuredValidated: SessionStore["createSecuredValidated"]): SessionStore {
  return { createSecuredValidated } as unknown as SessionStore;
}

function mockSession(id = "gmail-session", label = "person@example.com"): AccountSession {
  return { id, label } as AccountSession;
}

describe("Google OAuth provider compatibility", () => {
  it("accepts Google's canonical userinfo.email grant as equivalent to OIDC email", async () => {
    expect(googleScopeGranted(["openid", "https://www.googleapis.com/auth/userinfo.email"], "email")).toBe(true);
    expect(googleScopeGranted(["openid", "email"], "email")).toBe(true);
    expect(googleScopeGranted(["openid"], "email")).toBe(false);

    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({
      access_token: "access-token-private",
      expires_in: 3600,
      refresh_token: "refresh-token-private",
      id_token: "id-token-private",
      scope: `openid https://www.googleapis.com/auth/userinfo.email ${GOOGLE_GMAIL_MODIFY_SCOPE}`,
      token_type: "Bearer",
    }), { status: 200, headers: { "Content-Type": "application/json" } })));

    const result = await new DefaultGoogleOAuthRuntime().exchangeAuthorizationCode({
      clientId: "desktop-client.apps.googleusercontent.com",
      code: "authorization-code-private",
      codeVerifier: "a".repeat(64),
      redirectUri: "http://127.0.0.1:43123",
    });

    expect(result.refreshToken).toBe("refresh-token-private");
    expect(result.grantedScopes).toContain("https://www.googleapis.com/auth/userinfo.email");
  });

  it("returns ES-GOOGLE-01 for token exchange failure without exposing provider details", async () => {
    const secret = "authorization-code-private";
    const runtime: GoogleOAuthRuntime = {
      async exchangeAuthorizationCode() { throw new Error(`invalid_client ${secret}`); },
      async verifyIdToken() { throw new Error("must not be reached"); },
    };
    const manager = new GoogleOAuthFlowManager({
      clientId: "desktop-client.apps.googleusercontent.com",
      sessionStore: {} as SessionStore,
      runtime,
    });
    managers.push(manager);
    const started = await manager.start();
    const { redirect, state } = callbackParts(started.authorizationUrl);

    const response = await fetch(`${redirect}/?state=${encodeURIComponent(state)}&code=${secret}`);
    const body = await response.text();
    expect(response.status).toBe(502);
    expect(body).toContain("ES-GOOGLE-01");
    expect(body).not.toContain(secret);
    expect(body).not.toContain("invalid_client");
    expect(manager.status(started.flowId)).toMatchObject({ status: "error", error: expect.stringContaining("ES-GOOGLE-01") });
  });

  it("returns ES-GOOGLE-03 when Google signs in but Gmail API validation fails", async () => {
    let expectedNonce = "";
    const refreshToken = "refresh-token-private";
    const runtime: GoogleOAuthRuntime = {
      async exchangeAuthorizationCode() {
        return {
          refreshToken,
          idToken: "id-token-private",
          grantedScopes: ["openid", "email", GOOGLE_GMAIL_MODIFY_SCOPE],
        };
      },
      async verifyIdToken() {
        return {
          sub: "stable-google-subject",
          email: "person@example.com",
          emailVerified: true,
          nonce: expectedNonce,
        };
      },
    };
    const store = fakeSessionStore(async (_provider, _label, _config, validate) => {
      await validate();
      return mockSession();
    });
    const manager = new GoogleOAuthFlowManager({
      clientId: "desktop-client.apps.googleusercontent.com",
      sessionStore: store,
      runtime,
      async validateProvider(_config: AdapterConfig) { throw new Error(`gmail backend rejected ${refreshToken}`); },
    });
    managers.push(manager);
    const started = await manager.start();
    const { redirect, state, nonce } = callbackParts(started.authorizationUrl);
    expectedNonce = nonce;

    const response = await fetch(`${redirect}/?state=${encodeURIComponent(state)}&code=valid-code`);
    const body = await response.text();
    expect(response.status).toBe(502);
    expect(body).toContain("ES-GOOGLE-03");
    expect(body).toContain("Gmail API validation failed");
    expect(body).not.toContain(refreshToken);
    expect(body).not.toContain("backend rejected");
  });

  it("returns ES-GOOGLE-04 for protected local account setup failure without exposing lower-layer text", async () => {
    let expectedNonce = "";
    const secret = "vault-secret-private";
    const runtime: GoogleOAuthRuntime = {
      async exchangeAuthorizationCode() {
        return {
          refreshToken: "refresh-token-private",
          idToken: "id-token-private",
          grantedScopes: ["openid", "email", GOOGLE_GMAIL_MODIFY_SCOPE],
        };
      },
      async verifyIdToken() {
        return {
          sub: "stable-google-subject",
          email: "person@example.com",
          emailVerified: true,
          nonce: expectedNonce,
        };
      },
    };
    const store = fakeSessionStore(async (_provider, _label, _config, validate) => {
      await validate();
      throw new Error(`credential vault failed ${secret}`);
    });
    const manager = new GoogleOAuthFlowManager({
      clientId: "desktop-client.apps.googleusercontent.com",
      sessionStore: store,
      runtime,
      async validateProvider() {},
    });
    managers.push(manager);
    const started = await manager.start();
    const { redirect, state, nonce } = callbackParts(started.authorizationUrl);
    expectedNonce = nonce;

    const response = await fetch(`${redirect}/?state=${encodeURIComponent(state)}&code=valid-code`);
    const body = await response.text();
    expect(response.status).toBe(502);
    expect(body).toContain("ES-GOOGLE-04");
    expect(body).not.toContain(secret);
    expect(body).not.toContain("credential vault failed");
  });
});
