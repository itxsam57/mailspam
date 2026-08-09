import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import type { AdapterConfig } from "../../server/src/api/adapterConfig.js";
import type { AccountSession, SessionStore } from "../../server/src/api/sessionStore.js";
import { policyAccountKey } from "../../server/src/api/policyPersistence.js";
import type { CredentialReference, CredentialVault, CredentialVaultCapabilities } from "../../server/src/security/credentialVault.js";
import {
  gmailRefreshTokenCredentialReference,
  materializeAdapterConfig,
  secureAdapterConfig,
} from "../../server/src/security/secureAdapterConfig.js";
import {
  buildGoogleAuthorizationUrl,
  createPkcePair,
  GOOGLE_GMAIL_MODIFY_SCOPE,
  GoogleOAuthFlowManager,
  type GoogleOAuthRuntime,
} from "../../server/src/oauth/googleOAuthFlow.js";

class TestVault implements CredentialVault {
  readonly values = new Map<string, string>();
  readonly writes: CredentialReference[] = [];

  capabilities(): CredentialVaultCapabilities {
    return {
      backend: "test-native",
      available: true,
      persistent: true,
      userBound: true,
      hardwareBacked: false,
      applicationBound: false,
    };
  }

  async write(reference: CredentialReference, secret: string): Promise<void> {
    this.writes.push({ ...reference });
    this.values.set(`${reference.kind}:${reference.id}`, secret);
  }
  async read(reference: CredentialReference): Promise<string | null> {
    return this.values.get(`${reference.kind}:${reference.id}`) ?? null;
  }
  async delete(reference: CredentialReference): Promise<void> {
    this.values.delete(`${reference.kind}:${reference.id}`);
  }
}

const managers: GoogleOAuthFlowManager[] = [];
afterEach(() => {
  for (const manager of managers.splice(0)) manager.close();
});

function unusedSessionStore(): SessionStore {
  return {} as SessionStore;
}

function mockSession(id: string, label: string): AccountSession {
  return { id, label } as AccountSession;
}

describe("guided Gmail OAuth security", () => {
  it("generates a high-entropy S256 PKCE verifier/challenge pair", () => {
    const first = createPkcePair();
    const second = createPkcePair();
    expect(first.verifier).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
    expect(first.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(first.challenge).toBe(createHash("sha256").update(first.verifier, "ascii").digest("base64url"));
    expect(second.verifier).not.toBe(first.verifier);
  });

  it("builds an installed-app authorization request without any client secret or token", () => {
    const url = new URL(buildGoogleAuthorizationUrl({
      clientId: "desktop-client.apps.googleusercontent.com",
      redirectUri: "http://127.0.0.1:43123",
      state: "state-value",
      nonce: "nonce-value",
      codeChallenge: "challenge-value",
    }));
    expect(url.origin).toBe("https://accounts.google.com");
    expect(url.pathname).toBe("/o/oauth2/v2/auth");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("redirect_uri")).toBe("http://127.0.0.1:43123");
    expect(url.searchParams.get("state")).toBe("state-value");
    expect(url.searchParams.get("nonce")).toBe("nonce-value");
    expect(url.searchParams.get("code_challenge")).toBe("challenge-value");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("access_type")).toBe("offline");
    const scopes = (url.searchParams.get("scope") ?? "").split(" ");
    expect(scopes).toContain("openid");
    expect(scopes).toContain("email");
    expect(scopes).toContain(GOOGLE_GMAIL_MODIFY_SCOPE);
    expect(url.searchParams.has("client_secret")).toBe(false);
    expect(url.searchParams.has("refresh_token")).toBe(false);
  });

  it("keys guided Gmail vault and policy identity by stable Google sub, not refresh token", async () => {
    const first = {
      provider: "gmail" as const,
      mode: "live" as const,
      credentials: {
        clientId: "desktop-client.apps.googleusercontent.com",
        refreshToken: "refresh-one",
        accountSubject: "109876543210987654321",
      },
    };
    const rotated = {
      ...first,
      credentials: { ...first.credentials, refreshToken: "refresh-two" },
    };
    expect(policyAccountKey(first)).toBe(policyAccountKey(rotated));
    expect(gmailRefreshTokenCredentialReference(first.credentials.clientId, first.credentials.accountSubject))
      .toEqual(gmailRefreshTokenCredentialReference(rotated.credentials.clientId, rotated.credentials.accountSubject));

    const vault = new TestVault();
    const secured = await secureAdapterConfig(first, vault);
    expect(vault.writes).toHaveLength(1);
    expect(vault.writes[0]?.kind).toBe("oauth-refresh-token");
    expect(JSON.stringify(secured.config)).not.toContain("refresh-one");
    expect(secured.vaultReferences).toHaveLength(1);
    expect(await materializeAdapterConfig(secured.config, vault)).toEqual(first);
  });

  it("keeps legacy Gmail developer credentials memory-only when no verified Google sub exists", async () => {
    const config = {
      provider: "gmail" as const,
      mode: "live" as const,
      credentials: {
        clientId: "legacy-client",
        clientSecret: "legacy-public-secret",
        refreshToken: "legacy-refresh-token",
      },
    };
    const vault = new TestVault();
    const secured = await secureAdapterConfig(config, vault);
    expect(vault.writes).toHaveLength(0);
    expect(secured.vaultReferences).toHaveLength(0);
    expect(JSON.stringify(secured.config)).toContain("memory");
    expect(await materializeAdapterConfig(secured.config, vault)).toEqual(config);
  });

  it("uses one-time state and does not consume a flow on an invalid-state callback", async () => {
    const manager = new GoogleOAuthFlowManager({
      clientId: "desktop-client.apps.googleusercontent.com",
      sessionStore: unusedSessionStore(),
    });
    managers.push(manager);
    const started = await manager.start();
    const auth = new URL(started.authorizationUrl);
    const redirect = auth.searchParams.get("redirect_uri")!;

    const wrong = await fetch(`${redirect}/?state=wrong&error=access_denied`);
    expect(wrong.status).toBe(400);
    expect(manager.status(started.flowId)).toEqual({ status: "pending" });

    const denied = await fetch(`${redirect}/?state=${encodeURIComponent(auth.searchParams.get("state")!)}&error=access_denied`);
    expect(denied.status).toBe(400);
    expect(manager.status(started.flowId)).toEqual({ status: "error", error: "Google access was not granted." });
  });

  it("completes the full callback path once and exposes no authorization secrets to the dashboard", async () => {
    const authorizationCode = "authorization-code-private";
    const refreshToken = "refresh-token-private";
    const idToken = "id-token-private";
    let expectedNonce = "";
    let exchangeCalls = 0;
    let validationConfig: AdapterConfig | null = null;
    let createdConfig: AdapterConfig | null = null;

    const runtime: GoogleOAuthRuntime = {
      async exchangeAuthorizationCode(input) {
        exchangeCalls += 1;
        expect(input.code).toBe(authorizationCode);
        expect(input.codeVerifier).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
        expect(input.redirectUri).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
        return {
          refreshToken,
          idToken,
          grantedScopes: ["openid", "email", GOOGLE_GMAIL_MODIFY_SCOPE],
        };
      },
      async verifyIdToken(input) {
        expect(input.idToken).toBe(idToken);
        return {
          sub: "stable-google-subject",
          email: "person@example.com",
          emailVerified: true,
          nonce: expectedNonce,
        };
      },
    };
    const sessionStore = {
      async createSecured(provider: string, label: string, config: AdapterConfig) {
        expect(provider).toBe("gmail");
        createdConfig = structuredClone(config);
        return mockSession("gmail-session-1", label);
      },
    } as unknown as SessionStore;
    const manager = new GoogleOAuthFlowManager({
      clientId: "desktop-client.apps.googleusercontent.com",
      sessionStore,
      runtime,
      async validateProvider(config) { validationConfig = structuredClone(config); },
    });
    managers.push(manager);

    const started = await manager.start();
    const auth = new URL(started.authorizationUrl);
    const redirect = auth.searchParams.get("redirect_uri")!;
    const state = auth.searchParams.get("state")!;
    expectedNonce = auth.searchParams.get("nonce")!;

    const response = await fetch(`${redirect}/?state=${encodeURIComponent(state)}&code=${encodeURIComponent(authorizationCode)}`);
    const callbackBody = await response.text();
    expect(response.status).toBe(200);
    expect(exchangeCalls).toBe(1);
    expect(validationConfig).toEqual(createdConfig);
    expect(createdConfig).toEqual({
      provider: "gmail",
      mode: "live",
      credentials: {
        clientId: "desktop-client.apps.googleusercontent.com",
        refreshToken,
        accountSubject: "stable-google-subject",
      },
    });

    const publicStatus = manager.status(started.flowId);
    expect(publicStatus).toEqual({
      status: "complete",
      accountId: "gmail-session-1",
      provider: "gmail",
      label: "person@example.com",
    });
    const publicSurface = `${callbackBody}\n${JSON.stringify(publicStatus)}`;
    for (const secret of [authorizationCode, refreshToken, idToken, expectedNonce]) {
      expect(publicSurface).not.toContain(secret);
    }
  });

  it("consumes a valid callback before token exchange so concurrent replay cannot exchange twice", async () => {
    let expectedNonce = "";
    let exchangeCalls = 0;
    let releaseExchange!: () => void;
    const exchangePause = new Promise<void>((resolve) => { releaseExchange = resolve; });
    let exchangeStarted!: () => void;
    const exchangeStartedPromise = new Promise<void>((resolve) => { exchangeStarted = resolve; });

    const runtime: GoogleOAuthRuntime = {
      async exchangeAuthorizationCode() {
        exchangeCalls += 1;
        exchangeStarted();
        await exchangePause;
        return {
          refreshToken: "replay-refresh-token",
          idToken: "replay-id-token",
          grantedScopes: ["openid", "email", GOOGLE_GMAIL_MODIFY_SCOPE],
        };
      },
      async verifyIdToken() {
        return {
          sub: "replay-subject",
          email: "replay@example.com",
          emailVerified: true,
          nonce: expectedNonce,
        };
      },
    };
    const sessionStore = {
      async createSecured(_provider: string, label: string) {
        return mockSession("replay-session", label);
      },
    } as unknown as SessionStore;
    const manager = new GoogleOAuthFlowManager({
      clientId: "desktop-client.apps.googleusercontent.com",
      sessionStore,
      runtime,
      async validateProvider() {},
    });
    managers.push(manager);

    const started = await manager.start();
    const auth = new URL(started.authorizationUrl);
    const redirect = auth.searchParams.get("redirect_uri")!;
    const state = auth.searchParams.get("state")!;
    expectedNonce = auth.searchParams.get("nonce")!;
    const callbackUrl = `${redirect}/?state=${encodeURIComponent(state)}&code=replay-code`;

    const first = fetch(callbackUrl);
    await exchangeStartedPromise;
    const replay = fetch(callbackUrl).catch(() => null);
    await new Promise((resolve) => setTimeout(resolve, 15));
    expect(exchangeCalls).toBe(1);
    releaseExchange();
    expect((await first).status).toBe(200);
    const replayResponse = await replay;
    if (replayResponse) expect([409, 502]).toContain(replayResponse.status);
    expect(exchangeCalls).toBe(1);
  });

  it("rejects an ID token nonce mismatch before provider validation or account creation", async () => {
    let createCalls = 0;
    let validationCalls = 0;
    const sessionStore = {
      async createSecured() { createCalls += 1; throw new Error("must not be reached"); },
    } as unknown as SessionStore;
    const runtime: GoogleOAuthRuntime = {
      async exchangeAuthorizationCode(input) {
        expect(input.code).toBe("authorization-code");
        expect(input.codeVerifier).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
        return {
          refreshToken: "refresh-token-that-must-not-escape",
          idToken: "test-id-token",
          grantedScopes: ["openid", "email", GOOGLE_GMAIL_MODIFY_SCOPE],
        };
      },
      async verifyIdToken() {
        return {
          sub: "stable-google-subject",
          email: "person@example.com",
          emailVerified: true,
          nonce: "wrong-nonce",
        };
      },
    };
    const manager = new GoogleOAuthFlowManager({
      clientId: "desktop-client.apps.googleusercontent.com",
      sessionStore,
      runtime,
      async validateProvider() { validationCalls += 1; },
    });
    managers.push(manager);
    const started = await manager.start();
    const auth = new URL(started.authorizationUrl);
    const redirect = auth.searchParams.get("redirect_uri")!;
    const state = auth.searchParams.get("state")!;

    const response = await fetch(`${redirect}/?state=${encodeURIComponent(state)}&code=authorization-code`);
    expect(response.status).toBe(502);
    expect(createCalls).toBe(0);
    expect(validationCalls).toBe(0);
    expect(manager.status(started.flowId).status).toBe("error");
    expect(await response.text()).not.toContain("refresh-token-that-must-not-escape");
  });

  it("expires an unfinished loopback authorization request", async () => {
    const manager = new GoogleOAuthFlowManager({
      clientId: "desktop-client.apps.googleusercontent.com",
      sessionStore: unusedSessionStore(),
      flowTtlMs: 20,
    });
    managers.push(manager);
    const started = await manager.start();
    await new Promise((resolve) => setTimeout(resolve, 35));
    expect(manager.status(started.flowId)).toEqual({
      status: "error",
      error: "The Google authorization request expired. Start again.",
    });
  });

  it("fails closed when no application-owned Google client ID is configured", async () => {
    const manager = new GoogleOAuthFlowManager({ clientId: "", sessionStore: unusedSessionStore() });
    managers.push(manager);
    expect(manager.configured()).toBe(false);
    await expect(manager.start()).rejects.toThrow(/not configured/i);
  });
});
