import { afterEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createDefaultPersonalPolicyRepository,
  EncryptedFilePolicyRepository,
  policyAccountKey,
} from "../../server/src/api/policyPersistence.js";
import type {
  CredentialReference,
  CredentialVault,
  CredentialVaultCapabilities,
} from "../../server/src/security/credentialVault.js";

const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-policy-key-"));
  temporaryDirectories.push(directory);
  return directory;
}

class TestVault implements CredentialVault {
  readonly values = new Map<string, string>();
  readonly writes: Array<{ reference: CredentialReference; secret: string }> = [];
  failWrite = false;
  corruptReadAfterWrite = false;

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
    if (this.failWrite) throw new Error("simulated vault failure with private detail");
    this.writes.push({ reference: { ...reference }, secret });
    this.values.set(`${reference.kind}:${reference.id}`, secret);
  }

  async read(reference: CredentialReference): Promise<string | null> {
    const value = this.values.get(`${reference.kind}:${reference.id}`) ?? null;
    if (value && this.corruptReadAfterWrite) return Buffer.alloc(32, 99).toString("base64");
    return value;
  }

  async delete(reference: CredentialReference): Promise<void> {
    this.values.delete(`${reference.kind}:${reference.id}`);
  }
}

function snapshot() {
  return {
    blockedSenders: ["blocked@example.com"],
    blockedDomains: ["example.test"],
    trustedSenders: [],
    approvedExceptions: [],
    unsubscribedActions: [],
    reportedCampaigns: [],
  };
}

function prepareLegacyDatabase(directory: string, key: Buffer) {
  const accountKey = policyAccountKey({ provider: "icloud", mode: "fixture" });
  const repository = new EncryptedFilePolicyRepository(directory, key);
  repository.save(accountKey, snapshot());
  writeFileSync(join(directory, "personal-policy.key"), key, { mode: 0o600 });
  return accountKey;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("personal-policy encryption-key vault migration", () => {
  it("migrates a valid legacy key to one local-encryption-key vault record before deleting the raw file", async () => {
    const directory = temporaryDirectory();
    const key = Buffer.alloc(32, 17);
    const accountKey = prepareLegacyDatabase(directory, key);
    const vault = new TestVault();

    const repository = await createDefaultPersonalPolicyRepository({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    });

    expect(repository.persistent).toBe(true);
    expect(repository.load(accountKey)).toEqual(snapshot());
    expect(existsSync(join(directory, "personal-policy.key"))).toBe(false);
    expect(vault.writes).toHaveLength(1);
    expect(vault.writes[0]?.reference.kind).toBe("local-encryption-key");
    expect(vault.writes[0]?.reference.id).not.toContain("icloud");
    expect(Buffer.from(vault.writes[0]!.secret, "base64")).toEqual(key);

    const restarted = await createDefaultPersonalPolicyRepository({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    });
    expect(restarted.load(accountKey)).toEqual(snapshot());
    expect(vault.writes).toHaveLength(1);
  });

  it("keeps the legacy key file and encrypted database intact when protected storage fails", async () => {
    const directory = temporaryDirectory();
    const key = Buffer.alloc(32, 18);
    const accountKey = prepareLegacyDatabase(directory, key);
    const vault = new TestVault();
    vault.failWrite = true;

    await expect(createDefaultPersonalPolicyRepository({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    })).rejects.toThrow();

    expect(existsSync(join(directory, "personal-policy.key"))).toBe(true);
    expect(new EncryptedFilePolicyRepository(directory, key).load(accountKey)).toEqual(snapshot());
  });

  it("does not delete the legacy key when Credential Manager read-back differs", async () => {
    const directory = temporaryDirectory();
    const key = Buffer.alloc(32, 19);
    prepareLegacyDatabase(directory, key);
    const vault = new TestVault();
    vault.corruptReadAfterWrite = true;

    await expect(createDefaultPersonalPolicyRepository({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    })).rejects.toThrow(/verification failed/i);
    expect(existsSync(join(directory, "personal-policy.key"))).toBe(true);
  });

  it("fails closed if an existing protected key disagrees with the legacy key", async () => {
    const directory = temporaryDirectory();
    const legacyKey = Buffer.alloc(32, 20);
    prepareLegacyDatabase(directory, legacyKey);
    const vault = new TestVault();
    const protectedKey = Buffer.alloc(32, 21).toString("base64");
    await vault.write({ id: "personal-policy-encryption-key-v1", kind: "local-encryption-key" }, protectedKey);

    await expect(createDefaultPersonalPolicyRepository({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    })).rejects.toThrow();
    expect(existsSync(join(directory, "personal-policy.key"))).toBe(true);
  });

  it("generates a new protected key without ever creating personal-policy.key", async () => {
    const directory = temporaryDirectory();
    const vault = new TestVault();
    const repository = await createDefaultPersonalPolicyRepository({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    });
    const accountKey = policyAccountKey({ provider: "gmail", mode: "fixture" });
    repository.save(accountKey, snapshot());

    expect(repository.persistent).toBe(true);
    expect(existsSync(join(directory, "personal-policy.key"))).toBe(false);
    expect(vault.writes).toHaveLength(1);
    expect(Buffer.from(vault.writes[0]!.secret, "base64")).toHaveLength(32);

    const restarted = await createDefaultPersonalPolicyRepository({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    });
    expect(restarted.load(accountKey)).toEqual(snapshot());
  });

  it("uses memory-only policy state on a fresh unsupported platform instead of creating a plaintext key", async () => {
    const directory = temporaryDirectory();
    const repository = await createDefaultPersonalPolicyRepository({
      dataDirectory: directory,
      credentialVault: new TestVault(false),
      platform: "linux",
    });
    const accountKey = policyAccountKey({ provider: "outlook", mode: "fixture" });
    repository.save(accountKey, snapshot());

    expect(repository.persistent).toBe(false);
    expect(repository.load(accountKey)).toEqual(snapshot());
    expect(existsSync(join(directory, "personal-policy.key"))).toBe(false);
    expect(existsSync(join(directory, "personal-policies.enc.json"))).toBe(false);
  });

  it("preserves an existing unsupported-platform legacy database without creating or deleting key material", async () => {
    const directory = temporaryDirectory();
    const key = Buffer.alloc(32, 22);
    const accountKey = prepareLegacyDatabase(directory, key);
    const repository = await createDefaultPersonalPolicyRepository({
      dataDirectory: directory,
      credentialVault: new TestVault(false),
      platform: "linux",
    });

    expect(repository.persistent).toBe(true);
    expect(repository.load(accountKey)).toEqual(snapshot());
    expect(existsSync(join(directory, "personal-policy.key"))).toBe(true);
  });

  it("refuses an encrypted database when no protected or legacy key can be recovered", async () => {
    const directory = temporaryDirectory();
    const key = Buffer.alloc(32, 23);
    const accountKey = policyAccountKey({ provider: "yahoo", mode: "fixture" });
    new EncryptedFilePolicyRepository(directory, key).save(accountKey, snapshot());

    await expect(createDefaultPersonalPolicyRepository({
      dataDirectory: directory,
      credentialVault: new TestVault(false),
      platform: "linux",
    })).rejects.toThrow(/no readable local encryption key/i);
  });
});
