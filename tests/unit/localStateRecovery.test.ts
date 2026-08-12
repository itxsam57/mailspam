import { createHash } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { archiveUnreadableLocalState } from "../../server/src/api/localStateRecovery.js";
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
  const directory = mkdtempSync(join(tmpdir(), "email-shield-local-recovery-"));
  temporaryDirectories.push(directory);
  return directory;
}

class RecoveryVault implements CredentialVault {
  readonly values = new Map<string, string>();

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
    this.values.set(`${reference.kind}:${reference.id}`, secret);
  }

  async read(reference: CredentialReference): Promise<string | null> {
    return this.values.get(`${reference.kind}:${reference.id}`) ?? null;
  }

  async delete(reference: CredentialReference): Promise<void> {
    this.values.delete(`${reference.kind}:${reference.id}`);
  }
}

const legacyPolicyReference = {
  id: "personal-policy-encryption-key-v1",
  kind: "local-encryption-key",
} as const;

function policySnapshot() {
  return {
    blockedSenders: ["preserved@example.com"],
    blockedDomains: [],
    trustedSenders: [],
    approvedExceptions: [],
    unsubscribedActions: [],
    reportedCampaigns: [],
  };
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("explicit unreadable local-state recovery", () => {
  it("archives exact encrypted bytes with a digest and permits a clean restart", async () => {
    const directory = temporaryDirectory();
    const databaseKey = Buffer.alloc(32, 41);
    const accountKey = policyAccountKey({ provider: "icloud", mode: "fixture" });
    new EncryptedFilePolicyRepository(directory, databaseKey).save(accountKey, policySnapshot());
    const databasePath = join(directory, "personal-policies.enc.json");
    const original = readFileSync(databasePath);
    const vault = new RecoveryVault();
    await vault.write(legacyPolicyReference, Buffer.alloc(32, 42).toString("base64"));

    const result = await archiveUnreadableLocalState({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
      now: new Date("2026-08-12T12:34:56.789Z"),
    });

    expect(result.archiveDirectory).toMatch(/local-state-recovery-2026-08-12T12-34-56-789Z-[a-f0-9]{8}$/);
    expect(result.archivedFiles).toEqual(["personal-policies.enc.json"]);
    expect(existsSync(databasePath)).toBe(false);
    expect(readFileSync(join(result.archiveDirectory!, "personal-policies.enc.json"))).toEqual(original);
    const manifestText = readFileSync(join(result.archiveDirectory!, "recovery-manifest.json"), "utf8");
    const manifest = JSON.parse(manifestText) as { reason: string; files: Array<{ name: string; size: number; sha256: string }> };
    expect(manifest.reason).toBe("unreadable-encrypted-local-state");
    expect(manifest.files).toEqual([{
      name: "personal-policies.enc.json",
      size: original.length,
      sha256: createHash("sha256").update(original).digest("hex"),
    }]);
    expect(manifestText).not.toContain(databaseKey.toString("base64"));
    expect(manifestText).not.toContain("authenticate data");

    const clean = await createDefaultPersonalPolicyRepository({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    });
    clean.save(accountKey, policySnapshot());
    expect(clean.load(accountKey)).toEqual(policySnapshot());
  });

  it("migrates a readable legacy-key database without creating an archive", async () => {
    const directory = temporaryDirectory();
    const key = Buffer.alloc(32, 43);
    const accountKey = policyAccountKey({ provider: "gmail", mode: "fixture" });
    new EncryptedFilePolicyRepository(directory, key).save(accountKey, policySnapshot());
    const vault = new RecoveryVault();
    await vault.write(legacyPolicyReference, key.toString("base64"));

    const result = await archiveUnreadableLocalState({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    });

    expect(result).toEqual({ archiveDirectory: null, archivedFiles: [] });
    expect(existsSync(join(directory, "personal-policies.enc.json"))).toBe(true);
    expect(readdirSync(directory).some((name) => name.startsWith("local-state-recovery-"))).toBe(false);
  });

  it("moves nothing when a target is not a bounded regular file or the vault is unavailable", async () => {
    const malformedDirectory = temporaryDirectory();
    mkdirSync(join(malformedDirectory, "personal-policies.enc.json"));
    await expect(archiveUnreadableLocalState({
      dataDirectory: malformedDirectory,
      credentialVault: new RecoveryVault(),
      platform: "win32",
    })).rejects.toThrow(/bounded regular encrypted-state file/i);
    expect(existsSync(join(malformedDirectory, "personal-policies.enc.json"))).toBe(true);

    const unavailableDirectory = temporaryDirectory();
    const key = Buffer.alloc(32, 44);
    new EncryptedFilePolicyRepository(unavailableDirectory, key).save(
      policyAccountKey({ provider: "yahoo", mode: "fixture" }),
      policySnapshot(),
    );
    await expect(archiveUnreadableLocalState({
      dataDirectory: unavailableDirectory,
      credentialVault: new RecoveryVault(false),
      platform: "linux",
    })).rejects.toThrow(/requires the platform credential vault/i);
    expect(existsSync(join(unavailableDirectory, "personal-policies.enc.json"))).toBe(true);
  });
});
