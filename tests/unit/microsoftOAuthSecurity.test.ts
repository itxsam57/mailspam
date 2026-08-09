import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AdapterConfig } from "../../server/src/api/adapterConfig.js";
import type { AccountSession, SessionStore } from "../../server/src/api/sessionStore.js";
import { policyAccountKey } from "../../server/src/api/policyPersistence.js";
import type { CredentialReference, CredentialVault, CredentialVaultCapabilities } from "../../server/src/security/credentialVault.js";
import {
  materializeAdapterConfig,
  outlookRefreshTokenCredentialReference,
  replaceSecureOutlookRefreshToken,
  secureAdapterConfig,
} from "../../server/src/security/secureAdapterConfig.js";
import {
  exchangeMicrosoftAuthorizationCode,
  MICROSOFT_MAIL_READWRITE_SCOPE,
  MICROSOFT_OFFLINE_SCOPE,
  MICROSOFT_USER_READ_SCOPE,
} from "../../server/src/oauth/microsoftOAuth.js";
import {
  buildMicrosoftAuthorizationUrl,
  createMicrosoftPkcePair,
  MicrosoftOAuthFlowManager,
  type MicrosoftOAuthRuntime,
} from "../../server/src/oauth/microsoftOAuthFlow.js";

class TestVault implements CredentialVault {
  readonly values = new Map<string, string>();
  readonly writes: Array<{ reference: CredentialReference; secret: string }> = [];

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
    this.writes.push({ reference: { ...reference }, secret });
    this.values.set(`${reference.kind}:${reference.id}`, secret);
  }
  async read(reference: CredentialReference): Promise<string | null> {
    return this.values.get(`${reference.kind}:${reference.id}`) ?? null;
  }
  async delete(reference: CredentialReference): Promise<void> {
    this.values.delete(`${reference.kind}:${reference.id}`);
  }
}

const managers: MicrosoftOAuthFlowManager[] = [];
afterEach(() => {
  for (const manager of managers.splice(0)) manager.close();
  vi.unstubAllGlobals();
});

function unusedSessionStore(): SessionStore {
  return {} as SessionStore;
}

function mockSession(id: string, label: string): AccountSession {
  return { id, label } as AccountSession;
}

function callbackParts(started: { authorizationUrl: string }) {
  const auth = new URL(started.authorizationUrl);
  return {
    auth,
    redirect: auth.searchParams.get("redirect_uri")!,
    state: auth.searchParams.get("state")!,
  };
}

describe("guided Microsoft Outlook OAuth security", () => {
  it("generates a high-entropy S256 PKCE verifier/challenge pair", () => {
    const first = createMicrosoftPkcePair();
    const second = createMicrosoftPkcePair();
    expect(first.verifier).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
    expect(first.challenge).toBe(createHash("sha256").update(first.verifier, "ascii").digest("base64url"));
    expect(second.verifier).not.toBe(first.verifier);
  });

  it("builds a public-client system-browser request with only least-required Outlook scopes", () => {
    const url = new URL(buildMicrosoftAuthorizationUrl({
      clientId: "public-desktop-client-id",
      redirectUri: "http://localhost:43123",
      state: "state-value",
      codeChallenge: "challenge-value",
    }));
    expect(url.origin).toBe("https://login.microsoftonline.com");
    expect(url.pathname).toBe("/common/oauth2/v2.0/authorize");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("response_mode")).toBe("query");
    expect(url.searchParams.get("redirect_uri")).toBe("http://localhost:43123");
    expect(url.searchParams.get("state")).toBe("state-value");
    expect(url.searchParams.get("code_challenge")).toBe("challenge-value");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    const scopes = (url.searchParams.get("scope") ?? "").split(" ");
    expect(scopes).toEqual([MICROSOFT_OFFLINE_SCOPE, MICROSOFT_USER_READ_SCOPE, MICROSOFT_MAIL_READWRITE_SCOPE]);
    expect(scopes).not.toContain("Mail.Send");
    expect(url.searchParams.has("client_secret")).toBe(false);
    expect(url.searchParams.has("refresh_token")).toBe(false);
  });

  it("posts authorization code + PKCE without a client secret", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const form = init?.body as URLSearchParams;
      expect(form.get("client_id")).toBe("public-client-id");
      expect(form.get("code")).toBe("authorization-code-private");
      expect(form.get("code_verifier")).toBe("a".repeat(64));
      expect(form.get("redirect_uri")).toBe("http://localhost:43123");
      expect(form.has("client_secret")).toBe(false);
      return new Response(JSON.stringify({
        access_token: "access-private",
        refresh_token: "refresh-private",
        scope: "offline_access User.Read Mail.ReadWrite",
      }), { status: 200, headers: { "Content-Type": "application/json" } });
    });
    vi.stubGlobal("fetch", fetchMock);

    const result = await exchangeMicrosoftAuthorizationCode({
      clientId: "public-client-id",
      code: "authorization-code-private",
      codeVerifier: "a".repeat(64),
      redirectUri: "http://localhost:43123",
    });
    expect(result.refreshToken).toBe("refresh-private");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("keys guided Outlook vault and policy identity by stable Graph account ID, not rotating refresh token", async () => {
    const first: AdapterConfig = {
      provider: "outlook",
      mode: "live",
      credentials: {
        clientId: "public-client-id",
        refreshToken: "refresh-one",
        accountId: "stable-graph-account-id",
      },
    };
    const rotated: AdapterConfig = {
      ...first,
      credentials: { ...first.credentials, refreshToken: "refresh-two" },
    };
    expect(policyAccountKey(first)).toBe(policyAccountKey(rotated));
    expect(outlookRefreshTokenCredentialReference("public-client-id", "stable-graph-account-id"))
      .toEqual(outlookRefreshTokenCredentialReference("public-client-id", "stable-graph-account-id"));

    const vault = new TestVault();
    const secured = await secureAdapterConfig(first, vault);
    expect(vault.writes).toHaveLength(1);
    expect(vault.writes[0]?.reference.kind).toBe("oauth-refresh-token");
    expect(JSON.stringify(secured.config)).not.toContain("refresh-one");
    expect(await materializeAdapterConfig(secured.config, vault)).toEqual(first);

    if (secured.config.mode !== "live" || secured.config.provider !== "outlook") throw new Error("expected secured Outlook config");
    await replaceSecureOutlookRefreshToken(secured.config, vault, "refresh-two");
    const materialized = await materializeAdapterConfig(secured.config, vault);
    expect(materialized.mode === "live" && materialized.provider === "outlook" && materialized.credentials.refreshToken)
      .toBe("refresh-two");
    expect(vault.writes[1]?.reference).toEqual(vault.writes[0]?.reference);
  });

  it("keeps legacy Outlook developer credentials memory-only without stable Graph account ID", async () => {
    const config: AdapterConfig = {
      provider: "outlook",
      mode: "live",
      credentials: {
        clientId: "legacy-client",
        clientSecret: "legacy-secret",
        tenantId: "common",
        refreshToken: "legacy-refresh",
      },
    };
    const vault = new TestVault();
    const secured = await secureAdapterConfig(config, vault);
    expect(vault.writes).toHaveLength(0);
    expect(secured.vaultReferences).toHaveLength(0);
    expect(JSON.stringify(secured.config)).toContain("memory");
    expect(await materializeAdapterConfig(secured.config, vault)).toEqual(config);
  });

  it("completes one callback and exposes no Microsoft OAuth secrets to the browser", async () => {
    const authorizationCode = "authorization-code-private";
    const accessToken = "access-token-private";
    const refreshToken = "refresh-token-private";
    let exchangeCalls = 0;
    let createdConfig: AdapterConfig | null = null;
    const runtime: MicrosoftOAuthRuntime = {
      async exchangeAuthorizationCode(input) {
        exchangeCalls += 1;
        expect(input.code).toBe(authorizationCode);
        expect(input.codeVerifier).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
        expect(input.redirectUri).toMatch(/^http:\/\/localhost:\d+$/);
        return {
          accessToken,
          refreshToken,
          grantedScopes: [MICROSOFT_OFFLINE_SCOPE, MICROSOFT_USER_READ_SCOPE, MICROSOFT_MAIL_READWRITE_SCOPE],
        };
      },
      async validateMailbox(receivedAccessToken) {
        expect(receivedAccessToken).toBe(accessToken);
        return { accountId: "stable-graph-account-id", label: "person@example.com" };
      },
    };
    const store = {
      async createSecured(provider: string, label: string, config: AdapterConfig) {
        expect(provider).toBe("outlook");
        createdConfig = structuredClone(config);
        return mockSession("outlook-session-1", label);
      },
    } as unknown as SessionStore;
    const manager = new MicrosoftOAuthFlowManager({ clientId: "public-client-id", sessionStore: store, runtime });
    managers.push(manager);
    const started = await manager.start();
    const { redirect, state } = callbackParts(started);

    const response = await fetch(`${redirect}/?state=${encodeURIComponent(state)}&code=${encodeURIComponent(authorizationCode)}`);
    const callbackBody = await response.text();
    expect(response.status).toBe(200);
    expect(exchangeCalls).toBe(1);
    expect(createdConfig).toEqual({
      provider: "outlook",
      mode: "live",
      credentials: {
        clientId: "public-client-id",
        refreshToken,
        accountId: "stable-graph-account-id",
      },
    });
    const status = manager.status(started.flowId);
    expect(status).toEqual({ status: "complete", accountId: "outlook-session-1", provider: "outlook", label: "person@example.com" });
    const publicSurface = `${callbackBody}\n${JSON.stringify(status)}`;
    for (const secret of [authorizationCode, accessToken, refreshToken]) expect(publicSurface).not.toContain(secret);
  });

  it("does not consume wrong-state, non-GET or non-root callback requests", async () => {
    const manager = new MicrosoftOAuthFlowManager({ clientId: "public-client-id", sessionStore: unusedSessionStore() });
    managers.push(manager);
    const started = await manager.start();
    const { redirect, state } = callbackParts(started);

    const wrong = await fetch(`${redirect}/?state=wrong&error=access_denied`);
    expect(wrong.status).toBe(400);
    expect(manager.status(started.flowId)).toEqual({ status: "pending" });

    const post = await fetch(`${redirect}/?state=${encodeURIComponent(state)}&error=access_denied`, { method: "POST" });
    expect(post.status).toBe(405);
    expect(manager.status(started.flowId)).toEqual({ status: "pending" });

    const wrongPath = await fetch(`${redirect}/favicon.ico?state=${encodeURIComponent(state)}`);
    expect(wrongPath.status).toBe(404);
    expect(manager.status(started.flowId)).toEqual({ status: "pending" });
  });

  it("consumes the valid callback before async token exchange so replay cannot redeem twice", async () => {
    let exchangeCalls = 0;
    let releaseExchange!: () => void;
    let signalStarted!: () => void;
    const pause = new Promise<void>((resolve) => { releaseExchange = resolve; });
    const startedExchange = new Promise<void>((resolve) => { signalStarted = resolve; });
    const runtime: MicrosoftOAuthRuntime = {
      async exchangeAuthorizationCode() {
        exchangeCalls += 1;
        signalStarted();
        await pause;
        return {
          accessToken: "access-private",
          refreshToken: "refresh-private",
          grantedScopes: [MICROSOFT_OFFLINE_SCOPE, MICROSOFT_USER_READ_SCOPE, MICROSOFT_MAIL_READWRITE_SCOPE],
        };
      },
      async validateMailbox() { return { accountId: "stable-id", label: "Outlook" }; },
    };
    const store = {
      async createSecured(_provider: string, label: string) { return mockSession("session", label); },
    } as unknown as SessionStore;
    const manager = new MicrosoftOAuthFlowManager({ clientId: "public-client-id", sessionStore: store, runtime });
    managers.push(manager);
    const started = await manager.start();
    const { redirect, state } = callbackParts(started);
    const callbackUrl = `${redirect}/?state=${encodeURIComponent(state)}&code=one-time-code`;

    const first = fetch(callbackUrl);
    await startedExchange;
    const replay = fetch(callbackUrl).catch(() => null);
    await new Promise((resolve) => setTimeout(resolve, 15));
    expect(exchangeCalls).toBe(1);
    releaseExchange();
    expect((await first).status).toBe(200);
    const replayResponse = await replay;
    if (replayResponse) expect([409, 502]).toContain(replayResponse.status);
    expect(exchangeCalls).toBe(1);
  });

  it("expires unfinished flows and fails closed without the application-owned client ID", async () => {
    const expiring = new MicrosoftOAuthFlowManager({
      clientId: "public-client-id",
      sessionStore: unusedSessionStore(),
      flowTtlMs: 20,
    });
    managers.push(expiring);
    const started = await expiring.start();
    await new Promise((resolve) => setTimeout(resolve, 35));
    expect(expiring.status(started.flowId)).toEqual({
      status: "error",
      error: "The Microsoft authorization request expired. Start again.",
    });

    const missing = new MicrosoftOAuthFlowManager({ clientId: "", sessionStore: unusedSessionStore() });
    managers.push(missing);
    expect(missing.configured()).toBe(false);
    await expect(missing.start()).rejects.toThrow(/not configured/i);
  });

  it("returns stage-safe errors without leaking lower-layer OAuth secrets", async () => {
    const secret = "provider-secret-error-detail";
    const runtime: MicrosoftOAuthRuntime = {
      async exchangeAuthorizationCode() { throw new Error(secret); },
      async validateMailbox() { throw new Error("must not run"); },
    };
    const manager = new MicrosoftOAuthFlowManager({ clientId: "public-client-id", sessionStore: unusedSessionStore(), runtime });
    managers.push(manager);
    const started = await manager.start();
    const { redirect, state } = callbackParts(started);
    const response = await fetch(`${redirect}/?state=${encodeURIComponent(state)}&code=private-code`);
    const body = await response.text();
    expect(response.status).toBe(502);
    expect(body).toContain("ES-MICROSOFT-01");
    expect(body).not.toContain(secret);
    expect(JSON.stringify(manager.status(started.flowId))).not.toContain(secret);
  });
});
