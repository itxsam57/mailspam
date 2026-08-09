import { afterEach, describe, expect, it, vi } from "vitest";
import { SessionStore } from "../../server/src/api/sessionStore.js";
import { InMemoryPolicyRepository } from "../../server/src/api/policyPersistence.js";
import type { AdapterConfig } from "../../server/src/api/adapterConfig.js";
import type { CredentialReference, CredentialVault, CredentialVaultCapabilities } from "../../server/src/security/credentialVault.js";
import {
  providerCredentialRevoker,
  type ProviderCredentialRevoker,
} from "../../server/src/security/providerCredentialRevocation.js";
import type { SecureAdapterConfig } from "../../server/src/security/secureAdapterConfig.js";
import {
  GoogleOAuthRevocationError,
  revokeGoogleOAuthToken,
} from "../../server/src/oauth/googleOAuthRevocation.js";

class TestVault implements CredentialVault {
  readonly values = new Map<string, string>();
  readonly deletes: CredentialReference[] = [];

  constructor(private readonly available = true) {}

  capabilities(): CredentialVaultCapabilities {
    return {
      backend: this.available ? "test-native" : "unsupported:test",
      available: this.available,
      persistent: this.available,
      userBound: this.available,
      hardwareBacked: false,
      applicationBound: false,
    };
  }
  async write(reference: CredentialReference, secret: string): Promise<void> {
    if (!this.available) throw new Error("Persistent vault write must not be used on this platform.");
    this.values.set(`${reference.kind}:${reference.id}`, secret);
  }
  async read(reference: CredentialReference): Promise<string | null> {
    return this.values.get(`${reference.kind}:${reference.id}`) ?? null;
  }
  async delete(reference: CredentialReference): Promise<void> {
    this.deletes.push({ ...reference });
    this.values.delete(`${reference.kind}:${reference.id}`);
  }
}

function guidedGmail(refreshToken = "google-refresh-token"): AdapterConfig {
  return {
    provider: "gmail",
    mode: "live",
    credentials: {
      clientId: "desktop-client.apps.googleusercontent.com",
      refreshToken,
      accountSubject: "stable-google-subject",
    },
  };
}

async function secureRefreshToken(config: SecureAdapterConfig, vault: CredentialVault): Promise<string> {
  if (config.mode !== "live" || config.provider !== "gmail") throw new Error("Expected guided Gmail config");
  const handle = config.credentials.refreshToken;
  if (handle.storage === "memory") return handle.value;
  return (await vault.read(handle.reference)) ?? "";
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Google OAuth revocation", () => {
  it("posts the token in a form body and accepts Google's 200 confirmation", async () => {
    const token = "refresh-token-private-value";
    const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      expect(String(url)).toBe("https://oauth2.googleapis.com/revoke");
      expect(init?.method).toBe("POST");
      expect(new Headers(init?.headers).get("content-type")).toBe("application/x-www-form-urlencoded");
      expect(String(init?.body)).toBe(`token=${encodeURIComponent(token)}`);
      expect(String(url)).not.toContain(token);
      return new Response(null, { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);

    await expect(revokeGoogleOAuthToken(token)).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("treats Google's invalid_token response as an already-revoked terminal state", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(
      JSON.stringify({ error: "invalid_token" }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    )));
    await expect(revokeGoogleOAuthToken("already-invalid-token")).resolves.toBeUndefined();
  });

  it("fails closed on unconfirmed revocation without retaining provider response details", async () => {
    const secret = "private-refresh-token";
    vi.stubGlobal("fetch", vi.fn(async () => new Response(
      JSON.stringify({ error: "invalid_request", error_description: `bad ${secret}` }),
      { status: 400, headers: { "Content-Type": "application/json" } },
    )));

    try {
      await revokeGoogleOAuthToken(secret);
      throw new Error("Expected revocation failure");
    } catch (error) {
      expect(error).toBeInstanceOf(GoogleOAuthRevocationError);
      expect(String(error)).not.toContain(secret);
      expect(String(error)).not.toContain("invalid_request");
    }
  });
});

describe("guided Gmail final-session cleanup", () => {
  it("revokes only when the final same-account vault session is removed", async () => {
    const vault = new TestVault();
    const revoked: string[] = [];
    const revoker: ProviderCredentialRevoker = {
      requiresRevocation(config) {
        return config.mode === "live" && config.provider === "gmail" && Boolean(config.credentials.accountSubject);
      },
      async revoke(config, credentialVault) {
        revoked.push(await secureRefreshToken(config, credentialVault));
      },
    };
    const store = new SessionStore(new InMemoryPolicyRepository(), vault, revoker);
    const first = await store.createSecured("gmail", "first", guidedGmail("token-one"));
    const second = await store.createSecured("gmail", "second", guidedGmail("token-two"));

    expect(first.policyAccountKey).toBe(second.policyAccountKey);
    expect(first.vaultReferences[0]).toEqual(second.vaultReferences[0]);
    await store.remove(first.id);
    expect(revoked).toEqual([]);
    expect(vault.deletes).toEqual([]);
    expect(store.get(second.id)).toBe(second);

    await store.remove(second.id);
    expect(revoked).toEqual(["token-two"]);
    expect(vault.deletes).toHaveLength(1);
    expect(vault.values.size).toBe(0);
  });

  it("revokes a guided Gmail memory-only session when no persistent native vault exists", async () => {
    const token = "memory-only-google-refresh";
    const vault = new TestVault(false);
    const fetchMock = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      expect(String(init?.body)).toBe(`token=${encodeURIComponent(token)}`);
      return new Response(null, { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const store = new SessionStore(new InMemoryPolicyRepository(), vault, providerCredentialRevoker);
    const session = await store.createSecured("gmail", "person@example.com", guidedGmail(token));

    expect(session.vaultReferences).toHaveLength(0);
    expect(JSON.stringify(session.config)).toContain("memory");
    await store.remove(session.id);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(session.config)).not.toContain(token);
  });

  it("keeps the final account and vault credential retryable when provider revocation cannot be confirmed", async () => {
    const vault = new TestVault();
    const revoker: ProviderCredentialRevoker = {
      requiresRevocation() { return true; },
      async revoke() { throw new GoogleOAuthRevocationError(); },
    };
    const store = new SessionStore(new InMemoryPolicyRepository(), vault, revoker);
    const session = await store.createSecured("gmail", "person@example.com", guidedGmail());

    await expect(store.remove(session.id)).rejects.toThrow("Google did not confirm OAuth access revocation");
    expect(store.get(session.id)).toBe(session);
    expect(vault.deletes).toHaveLength(0);
    expect(vault.values.size).toBe(1);
  });

  it("serializes reconnect validation+commit ahead of final-account revocation", async () => {
    const vault = new TestVault();
    let revokeCalls = 0;
    const revoker: ProviderCredentialRevoker = {
      requiresRevocation(config) {
        return config.mode === "live" && config.provider === "gmail" && Boolean(config.credentials.accountSubject);
      },
      async revoke() { revokeCalls += 1; },
    };
    const store = new SessionStore(new InMemoryPolicyRepository(), vault, revoker);
    const first = await store.createSecured("gmail", "old", guidedGmail("old-token"));

    let validationStarted!: () => void;
    let releaseValidation!: () => void;
    const validationStartedPromise = new Promise<void>((resolve) => { validationStarted = resolve; });
    const validationPause = new Promise<void>((resolve) => { releaseValidation = resolve; });
    const creating = store.createSecuredValidated(
      "gmail",
      "new",
      guidedGmail("new-token"),
      async () => {
        validationStarted();
        await validationPause;
      },
    );

    await validationStartedPromise;
    const removing = store.remove(first.id);
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(revokeCalls).toBe(0);
    expect(store.get(first.id)).toBeUndefined(); // closing sessions are hidden while removal waits

    releaseValidation();
    const second = await creating;
    await removing;

    expect(revokeCalls).toBe(0);
    expect(store.get(second.id)).toBe(second);
    expect((await store.materializeConfig(second) as Extract<AdapterConfig, { provider: "gmail" }>).credentials.refreshToken)
      .toBe("new-token");
  });

  it("does not invoke provider revocation for non-OAuth app-password credentials", async () => {
    const vault = new TestVault();
    let revokeCalls = 0;
    const revoker: ProviderCredentialRevoker = {
      requiresRevocation() { return false; },
      async revoke() { revokeCalls += 1; },
    };
    const store = new SessionStore(new InMemoryPolicyRepository(), vault, revoker);
    const session = await store.createSecured("icloud", "icloud", {
      provider: "icloud",
      mode: "live",
      credentials: { user: "person@icloud.com", appPassword: "app-password-value" },
    });

    await store.remove(session.id);
    expect(revokeCalls).toBe(0);
    expect(vault.values.size).toBe(0);
  });
});
