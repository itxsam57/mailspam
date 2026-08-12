import { afterEach, describe, expect, it, vi } from "vitest";
import type { AccountSession, SessionStore } from "../../server/src/api/sessionStore.js";
import type { AdapterConfig } from "../../server/src/api/adapterConfig.js";
import {
  buildGoogleAuthorizationUrl,
  DefaultGoogleOAuthRuntime,
  GOOGLE_GMAIL_MODIFY_SCOPE,
  GoogleOAuthFlowManager,
  googleScopeGranted,
  type GoogleOAuthRuntime,
} from "../../server/src/oauth/googleOAuthFlow.js";

const managers: GoogleOAuthFlowManager[] = [];
const originalGoogleClientSecret = process.env.EMAIL_SHIELD_GOOGLE_CLIENT_SECRET;

afterEach(() => {
  for (const manager of managers.splice(0)) manager.close();
  vi.unstubAllGlobals();
  if (originalGoogleClientSecret === undefined) delete process.env.EMAIL_SHIELD_GOOGLE_CLIENT_SECRET;
  else process.env.EMAIL_SHIELD_GOOGLE_CLIENT_SECRET = originalGoogleClientSecret;
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
  it("requests fresh consent for every explicit protected offline Gmail connection", () => {
    const authorization = new URL(buildGoogleAuthorizationUrl({
      clientId: "desktop-client.apps.googleusercontent.com",
      redirectUri: "http://127.0.0.1:43123",
      state: "state-value",
      nonce: "nonce-value",
      codeChallenge: "challenge-value",
    }));

    expect(authorization.searchParams.get("access_type")).toBe("offline");
    expect(authorization.searchParams.get("prompt")).toBe("consent");
    expect(authorization.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorization.searchParams.get("client_secret")).toBeNull();
    expect(authorization.searchParams.get("scope")?.split(" ")).toEqual(expect.arrayContaining([
      "openid",
      "email",
      GOOGLE_GMAIL_MODIFY_SCOPE,
    ]));
  });

  it("posts an optional matching client value only to Google's token endpoint", async () => {
    const clientSecret = "desktop-client-secret-private";
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = init?.body;
      expect(body).toBeInstanceOf(URLSearchParams);
      const form = body as URLSearchParams;
      expect(form.get("client_id")).toBe("desktop-client.apps.googleusercontent.com");
      expect(form.get("client_secret")).toBe(clientSecret);
      expect(form.get("code")).toBe("authorization-code-private");
      expect(form.get("code_verifier")).toBe("a".repeat(64));
      expect(form.get("redirect_uri")).toBe("http://127.0.0.1:43123");
      return new Response(JSON.stringify({
        access_token: "access-token-private",
        expires_in: 3600,
        refresh_token: "refresh-token-private",
        id_token: "id-token-private",
        scope: `openid https://www.googleapis.com/auth/userinfo.email ${GOOGLE_GMAIL_MODIFY_SCOPE}`,
        token_type: "Bearer",
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await new DefaultGoogleOAuthRuntime().exchangeAuthorizationCode({
      clientId: "desktop-client.apps.googleusercontent.com",
      clientSecret,
      code: "authorization-code-private",
      codeVerifier: "a".repeat(64),
      redirectUri: "http://127.0.0.1:43123",
    });

    expect(result.refreshToken).toBe("refresh-token-private");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

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
      clientSecret: "desktop-client-secret-private",
      code: "authorization-code-private",
      codeVerifier: "a".repeat(64),
      redirectUri: "http://127.0.0.1:43123",
    });

    expect(result.refreshToken).toBe("refresh-token-private");
    expect(result.grantedScopes).toContain("https://www.googleapis.com/auth/userinfo.email");
  });

  it("uses the process-local client value only at OAuth exchange and excludes it from the persistent Gmail session", async () => {
    process.env.EMAIL_SHIELD_GOOGLE_CLIENT_SECRET = "process-client-secret-private";
    let expectedNonce = "";
    let exchangeSecret: string | undefined;
    let committedClientSecret: string | undefined;
    const runtime: GoogleOAuthRuntime = {
      async exchangeAuthorizationCode(input) {
        exchangeSecret = input.clientSecret;
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
    const store = fakeSessionStore(async (_provider, _label, config, validate) => {
      const runtimeConfig = config as AdapterConfig;
      if (runtimeConfig.provider === "gmail" && runtimeConfig.mode === "live") {
        committedClientSecret = runtimeConfig.credentials.clientSecret;
      }
      await validate();
      return mockSession();
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
    expect(response.status).toBe(200);
    expect(exchangeSecret).toBe("process-client-secret-private");
    expect(committedClientSecret).toBeUndefined();
    expect(body).not.toContain("process-client-secret-private");
    expect(manager.status(started.flowId)).toMatchObject({ status: "complete", provider: "gmail" });
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
