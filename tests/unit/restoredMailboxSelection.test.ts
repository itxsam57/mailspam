import { describe, expect, it } from "vitest";
import { InMemoryLiveConnectionPersistence } from "../../server/src/api/liveConnectionPersistence.js";
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

describe("restored mailbox workspace selection", () => {
  it("selects the only restored mailbox after process restart", async () => {
    const registry = new InMemoryLiveConnectionPersistence();
    const vault = new TestVault();
    const first = new SessionStore(new InMemoryPolicyRepository(), vault, noRevocation);
    first.configureLiveConnectionPersistence(registry);
    await first.createSecured("gmail", "Gmail", {
      provider: "gmail",
      mode: "live",
      credentials: {
        clientId: "desktop-client.apps.googleusercontent.com",
        refreshToken: "refresh-token",
        accountSubject: "google-subject-123",
      },
    });

    const second = new SessionStore(new InMemoryPolicyRepository(), vault, noRevocation);
    second.configureLiveConnectionPersistence(registry);
    const restored = second.restoreLiveConnections();

    expect(restored).toHaveLength(1);
    expect(second.workspaceSnapshot().selectedAccountId).toBe(restored[0]!.id);
  });

  it("does not guess a workspace mailbox when multiple mailboxes are restored", async () => {
    const registry = new InMemoryLiveConnectionPersistence();
    const vault = new TestVault();
    const first = new SessionStore(new InMemoryPolicyRepository(), vault, noRevocation);
    first.configureLiveConnectionPersistence(registry);
    await first.createSecured("gmail", "Gmail A", {
      provider: "gmail",
      mode: "live",
      credentials: {
        clientId: "desktop-client.apps.googleusercontent.com",
        refreshToken: "refresh-token-a",
        accountSubject: "google-subject-a",
      },
    });
    await first.createSecured("gmail", "Gmail B", {
      provider: "gmail",
      mode: "live",
      credentials: {
        clientId: "desktop-client.apps.googleusercontent.com",
        refreshToken: "refresh-token-b",
        accountSubject: "google-subject-b",
      },
    });

    const second = new SessionStore(new InMemoryPolicyRepository(), vault, noRevocation);
    second.configureLiveConnectionPersistence(registry);
    expect(second.restoreLiveConnections()).toHaveLength(2);
    expect(second.workspaceSnapshot().selectedAccountId).toBeNull();
  });
});
