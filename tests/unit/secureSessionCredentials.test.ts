import { describe, expect, it } from "vitest";
import { SessionStore } from "../../server/src/api/sessionStore.js";
import { InMemoryPolicyRepository, policyAccountKey } from "../../server/src/api/policyPersistence.js";
import type {
  CredentialReference,
  CredentialVault,
  CredentialVaultCapabilities,
} from "../../server/src/security/credentialVault.js";
import {
  appPasswordCredentialReference,
  type SecureAdapterConfig,
} from "../../server/src/security/secureAdapterConfig.js";

class TestCredentialVault implements CredentialVault {
  readonly values = new Map<string, string>();
  readonly writes: CredentialReference[] = [];
  readonly reads: CredentialReference[] = [];
  readonly deletes: CredentialReference[] = [];
  failWrite = false;
  failDelete = false;

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
    this.writes.push({ ...reference });
    if (this.failWrite) throw new Error("native write failed");
    this.values.set(`${reference.kind}:${reference.id}`, secret);
  }

  async read(reference: CredentialReference): Promise<string | null> {
    this.reads.push({ ...reference });
    return this.values.get(`${reference.kind}:${reference.id}`) ?? null;
  }

  async delete(reference: CredentialReference): Promise<void> {
    this.deletes.push({ ...reference });
    if (this.failDelete) throw new Error("native delete failed");
    this.values.delete(`${reference.kind}:${reference.id}`);
  }
}

function icloudConfig(user: string, appPassword: string) {
  return {
    provider: "icloud" as const,
    mode: "live" as const,
    credentials: { user, appPassword },
  };
}

describe("secure account-session credentials", () => {
  it("derives one deterministic opaque app-password reference per stable mailbox identity", () => {
    const first = appPasswordCredentialReference(icloudConfig("Person@icloud.com", "first-secret"));
    const rotated = appPasswordCredentialReference(icloudConfig("person@ICLOUD.COM", "rotated-secret"));
    const other = appPasswordCredentialReference(icloudConfig("other@icloud.com", "first-secret"));

    expect(first).toEqual(rotated);
    expect(first).not.toEqual(other);
    expect(first.id).toMatch(/^app-password-[a-f0-9]{64}$/);
    expect(first.id).not.toContain("person@icloud.com");
    expect(first.id).not.toContain("first-secret");
  });

  it("stores a validated app password in the native vault and keeps it out of session config", async () => {
    const vault = new TestCredentialVault();
    const store = new SessionStore(new InMemoryPolicyRepository(), vault);
    const rawSecret = "example-app-password";
    const session = await store.createSecured("icloud", "mailbox", icloudConfig("person@icloud.com", rawSecret));

    expect(vault.writes).toHaveLength(1);
    expect(JSON.stringify(session.config)).not.toContain(rawSecret);
    expect(session.vaultReferences).toHaveLength(1);
    expect((session.config as Extract<SecureAdapterConfig, { provider: "icloud" }>).credentials.appPassword)
      .toMatchObject({ storage: "vault" });

    const materialized = await store.materializeConfig(session);
    expect(materialized).toEqual(icloudConfig("person@icloud.com", rawSecret));
  });

  it("preserves personal-policy identity when an app password rotates", async () => {
    const vault = new TestCredentialVault();
    const repository = new InMemoryPolicyRepository();
    const store = new SessionStore(repository, vault);
    const oldConfig = icloudConfig("Person@icloud.com", "old-password");
    const newConfig = icloudConfig("person@ICLOUD.COM", "new-password");

    expect(policyAccountKey(oldConfig)).toBe(policyAccountKey(newConfig));
    const first = await store.createSecured("icloud", "first", oldConfig);
    first.personalPolicy.trustSender("trusted@example.com");
    store.persistPersonalPolicy(first);

    const second = await store.createSecured("icloud", "second", newConfig);
    expect(second.policyAccountKey).toBe(first.policyAccountKey);
    expect(second.personalPolicy).toBe(first.personalPolicy);
    expect(second.personalPolicy.isTrustedSender("trusted@example.com")).toBe(true);
    expect(first.vaultReferences[0]).toEqual(second.vaultReferences[0]);
    expect((await store.materializeConfig(first) as typeof oldConfig).credentials.appPassword).toBe("new-password");
  });

  it("does not delete a shared vault credential until the last same-account session is removed", async () => {
    const vault = new TestCredentialVault();
    const store = new SessionStore(new InMemoryPolicyRepository(), vault);
    const first = await store.createSecured("icloud", "first", icloudConfig("same@icloud.com", "password-one"));
    const second = await store.createSecured("icloud", "second", icloudConfig("SAME@ICLOUD.COM", "password-two"));

    await store.remove(first.id);
    expect(vault.deletes).toHaveLength(0);
    expect(await store.materializeConfig(second)).toMatchObject({
      credentials: { appPassword: "password-two" },
    });

    await store.remove(second.id);
    expect(vault.deletes).toHaveLength(1);
    expect(vault.values.size).toBe(0);
  });

  it("keeps the account present when last-reference native deletion fails", async () => {
    const vault = new TestCredentialVault();
    const store = new SessionStore(new InMemoryPolicyRepository(), vault);
    const session = await store.createSecured("icloud", "mailbox", icloudConfig("person@icloud.com", "secret"));
    vault.failDelete = true;

    await expect(store.remove(session.id)).rejects.toThrow("native delete failed");
    expect(store.get(session.id)).toBe(session);
    expect(vault.values.size).toBe(1);
  });

  it("fails session creation when an available native vault refuses the credential write", async () => {
    const vault = new TestCredentialVault();
    vault.failWrite = true;
    const store = new SessionStore(new InMemoryPolicyRepository(), vault);

    await expect(store.createSecured(
      "icloud",
      "mailbox",
      icloudConfig("person@icloud.com", "secret-that-must-not-fallback"),
    )).rejects.toThrow("native write failed");
    expect(store.list()).toHaveLength(0);
  });

  it("uses memory-only ephemeral credentials when no native persistent backend exists", async () => {
    const vault = new TestCredentialVault(false);
    const store = new SessionStore(new InMemoryPolicyRepository(), vault);
    const secret = "ephemeral-only";
    const session = await store.createSecured("icloud", "mailbox", icloudConfig("person@icloud.com", secret));

    expect(vault.writes).toHaveLength(0);
    expect(session.vaultReferences).toHaveLength(0);
    expect((session.config as Extract<SecureAdapterConfig, { provider: "icloud" }>).credentials.appPassword)
      .toMatchObject({ storage: "memory", value: secret });
    expect(await store.materializeConfig(session)).toEqual(icloudConfig("person@icloud.com", secret));

    await store.remove(session.id);
    expect(JSON.stringify(session.config)).not.toContain(secret);
  });
});
