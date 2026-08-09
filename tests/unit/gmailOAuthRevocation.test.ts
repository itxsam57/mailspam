import { afterEach, describe, expect, it, vi } from "vitest";
import { SessionStore } from "../../server/src/api/sessionStore.js";
import { InMemoryPolicyRepository } from "../../server/src/api/policyPersistence.js";
import type { AdapterConfig } from "../../server/src/api/adapterConfig.js";
import type { CredentialReference, CredentialVault, CredentialVaultCapabilities } from "../../server/src/security/credentialVault.js";
import type { ProviderCredentialRevoker } from "../../server/src/security/providerCredentialRevocation.js";
import {
  GoogleOAuthRevocationError,
  revokeGoogleOAuthToken,
} from "../../server/src/oauth/googleOAuthRevocation.js";

class TestVault implements CredentialVault {
  readonly values = new Map<string, string>();
  readonly deletes: CredentialReference[] = [];

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
  it("revokes only when the final same-account vault reference is removed", async () => {
    const vault = new TestVault();
    const revoked: string[] = [];
    const revoker: ProviderCredentialRevoker = {
      requiresRevocation(config, reference) {
        return config.mode === "live" && config.provider === "gmail" && reference.kind === "oauth-refresh-token";
      },
      async revoke(_config, _reference, secret) { revoked.push(secret); },
    };
    const store = new SessionStore(new InMemoryPolicyRepository(), vault, revoker);
    const first = await store.createSecured("gmail", "first", guidedGmail("token-one"));
    const second = await store.createSecured("gmail", "second", guidedGmail("token-two"));

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
