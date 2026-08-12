import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  EncryptedFileLiveConnectionPersistence,
  InMemoryLiveConnectionPersistence,
  persistentConnectionFromSession,
} from "../../server/src/api/liveConnectionPersistence.js";
import { InMemoryPolicyRepository } from "../../server/src/api/policyPersistence.js";
import { SessionStore } from "../../server/src/api/sessionStore.js";
import type {
  CredentialReference,
  CredentialVault,
  CredentialVaultCapabilities,
} from "../../server/src/security/credentialVault.js";
import type { ProviderCredentialRevoker } from "../../server/src/security/providerCredentialRevocation.js";

class TestVault implements CredentialVault {
  readonly secrets = new Map<string, string>();

  capabilities(): CredentialVaultCapabilities {
    return {
      backend: "test-persistent-vault",
      available: true,
      persistent: true,
      userBound: true,
      hardwareBacked: false,
      applicationBound: true,
    };
  }

  async write(reference: CredentialReference, secret: string): Promise<void> {
    this.secrets.set(`${reference.kind}:${reference.id}`, secret);
  }

  async read(reference: CredentialReference): Promise<string | null> {
    return this.secrets.get(`${reference.kind}:${reference.id}`) ?? null;
  }

  async delete(reference: CredentialReference): Promise<void> {
    this.secrets.delete(`${reference.kind}:${reference.id}`);
  }
}

const noRevocation: ProviderCredentialRevoker = {
  requiresRevocation: () => false,
  revoke: async () => undefined,
};

const roots: string[] = [];
function root(): string {
  const value = mkdtempSync(join(tmpdir(), "email-shield-live-connections-"));
  roots.push(value);
  return value;
}

afterEach(() => {
  while (roots.length) rmSync(roots.pop()!, { recursive: true, force: true });
});

describe("persistent live mailbox connections", () => {
  it("restores Gmail after process restart with the same policy identity and vault-only refresh token", async () => {
    const directory = root();
    const vault = new TestVault();
    const registry = new EncryptedFileLiveConnectionPersistence(directory, randomBytes(32));
    const policies = new InMemoryPolicyRepository();
    const first = new SessionStore(policies, vault, noRevocation);
    first.configureLiveConnectionPersistence(registry, { required: true });

    const original = await first.createSecured("gmail", "owner@example.com", {
      provider: "gmail",
      mode: "live",
      credentials: {
        clientId: "desktop-client.apps.googleusercontent.com",
        refreshToken: "google-refresh-secret",
        accountSubject: "google-subject-123",
      },
    });
    expect(original.config.mode).toBe("live");
    expect(persistentConnectionFromSession(original).provider).toBe("gmail");

    const raw = readFileSync(join(directory, "live-connections.enc.json"), "utf8");
    expect(raw).not.toContain("owner@example.com");
    expect(raw).not.toContain("google-refresh-secret");
    expect(raw).not.toContain("google-subject-123");
    expect(raw).not.toContain("desktop-client.apps.googleusercontent.com");

    const second = new SessionStore(policies, vault, noRevocation);
    second.configureLiveConnectionPersistence(registry, { required: true });
    const restored = second.restoreLiveConnections();
    expect(restored).toHaveLength(1);
    expect(restored[0]).toMatchObject({
      provider: "gmail",
      label: "owner@example.com",
      policyAccountKey: original.policyAccountKey,
    });
    const materialized = await second.materializeConfig(restored[0]!);
    expect(materialized).toEqual({
      provider: "gmail",
      mode: "live",
      credentials: {
        clientId: "desktop-client.apps.googleusercontent.com",
        refreshToken: "google-refresh-secret",
        accountSubject: "google-subject-123",
      },
    });
  });

  it.each([
    ["outlook", {
      provider: "outlook" as const,
      mode: "live" as const,
      credentials: {
        clientId: "microsoft-public-client",
        refreshToken: "microsoft-refresh-secret",
        accountId: "graph-account-123",
      },
    }],
    ["icloud", {
      provider: "icloud" as const,
      mode: "live" as const,
      credentials: { user: "person@icloud.com", appPassword: "icloud-app-password" },
    }],
    ["yahoo", {
      provider: "yahoo" as const,
      mode: "live" as const,
      credentials: { user: "person@yahoo.com", appPassword: "yahoo-app-password" },
    }],
    ["imap", {
      provider: "imap" as const,
      mode: "live" as const,
      credentials: {
        host: "imap.example.net",
        port: 993,
        secure: true,
        user: "person@example.net",
        appPassword: "generic-imap-password",
      },
    }],
  ] as const)("round-trips %s live metadata through encrypted restart restoration", async (_name, config) => {
    const directory = root();
    const vault = new TestVault();
    const registry = new EncryptedFileLiveConnectionPersistence(directory, randomBytes(32));
    const first = new SessionStore(new InMemoryPolicyRepository(), vault, noRevocation);
    first.configureLiveConnectionPersistence(registry, { required: true });
    const original = await first.createSecured(config.provider, `label-${config.provider}`, config);

    const second = new SessionStore(new InMemoryPolicyRepository(), vault, noRevocation);
    second.configureLiveConnectionPersistence(registry, { required: true });
    const [restored] = second.restoreLiveConnections();
    expect(restored).toBeDefined();
    expect(restored!.policyAccountKey).toBe(original.policyAccountKey);
    expect(restored!.provider).toBe(config.provider);
    const materialized = await second.materializeConfig(restored!);
    expect(materialized).toEqual(config);
  });

  it("rolls back the session and newly written vault secret when durable metadata cannot be committed", async () => {
    const vault = new TestVault();
    const failingRegistry = {
      persistent: true,
      list: () => [],
      remember: () => { throw new Error("disk write failed"); },
      remove: () => undefined,
    };
    const store = new SessionStore(new InMemoryPolicyRepository(), vault, noRevocation);
    store.configureLiveConnectionPersistence(failingRegistry, { required: true });

    await expect(store.createSecured("outlook", "Outlook", {
      provider: "outlook",
      mode: "live",
      credentials: {
        clientId: "microsoft-public-client",
        refreshToken: "must-be-cleaned-up",
        accountId: "graph-account-rollback",
      },
    })).rejects.toThrow("disk write failed");
    expect(store.list()).toEqual([]);
    expect(vault.secrets.size).toBe(0);
  });

  it("refuses a consumer live connection when only volatile connection persistence is available", async () => {
    const vault = new TestVault();
    const store = new SessionStore(new InMemoryPolicyRepository(), vault, noRevocation);
    store.configureLiveConnectionPersistence(new InMemoryLiveConnectionPersistence(), { required: true });

    await expect(store.createSecured("outlook", "Outlook", {
      provider: "outlook",
      mode: "live",
      credentials: {
        clientId: "microsoft-public-client",
        refreshToken: "not-written",
        accountId: "graph-account-volatile",
      },
    })).rejects.toThrow(/persistent live mailbox protection is unavailable/i);
    expect(vault.secrets.size).toBe(0);
  });

  it("rejects unstable raw Gmail and confidential-client Outlook connections from the persistent consumer registry", async () => {
    const vault = new TestVault();
    const registry = new InMemoryLiveConnectionPersistence();
    const store = new SessionStore(new InMemoryPolicyRepository(), vault, noRevocation);
    store.configureLiveConnectionPersistence(registry);

    await expect(store.createSecured("gmail", "Developer Gmail", {
      provider: "gmail",
      mode: "live",
      credentials: {
        clientId: "desktop-client",
        refreshToken: "developer-token-without-stable-subject",
      },
    })).rejects.toThrow(/account subject|native credential vault/i);

    await expect(store.createSecured("outlook", "Confidential Outlook", {
      provider: "outlook",
      mode: "live",
      credentials: {
        clientId: "confidential-client",
        clientSecret: "not-a-public-client",
        refreshToken: "developer-token",
        accountId: "graph-account-confidential",
      },
    })).rejects.toThrow(/confidential-client/i);
  });

  it("keeps the account descriptor when a protected vault secret later disappears, then fails materialization with reconnect guidance", async () => {
    const directory = root();
    const vault = new TestVault();
    const registry = new EncryptedFileLiveConnectionPersistence(directory, randomBytes(32));
    const first = new SessionStore(new InMemoryPolicyRepository(), vault, noRevocation);
    first.configureLiveConnectionPersistence(registry, { required: true });
    await first.createSecured("outlook", "Outlook", {
      provider: "outlook",
      mode: "live",
      credentials: {
        clientId: "microsoft-public-client",
        refreshToken: "rotatable-refresh-token",
        accountId: "graph-account-missing-secret",
      },
    });

    vault.secrets.clear();
    const second = new SessionStore(new InMemoryPolicyRepository(), vault, noRevocation);
    second.configureLiveConnectionPersistence(registry, { required: true });
    const [restored] = second.restoreLiveConnections();
    expect(restored).toBeDefined();
    expect(registry.list()).toHaveLength(1);
    await expect(second.materializeConfig(restored!)).rejects.toThrow(/reconnect the account/i);
  });

  it("removes the persistent descriptor when the final live session is disconnected", async () => {
    const vault = new TestVault();
    const registry = new InMemoryLiveConnectionPersistence();
    const store = new SessionStore(new InMemoryPolicyRepository(), vault, noRevocation);
    store.configureLiveConnectionPersistence(registry);
    const session = await store.createSecured("outlook", "Outlook", {
      provider: "outlook",
      mode: "live",
      credentials: {
        clientId: "microsoft-public-client",
        refreshToken: "disconnect-refresh-token",
        accountId: "graph-account-disconnect",
      },
    });
    expect(registry.list()).toHaveLength(1);
    await store.remove(session.id);
    expect(registry.list()).toHaveLength(0);
    expect(vault.secrets.size).toBe(0);
  });
});
