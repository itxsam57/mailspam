import { afterEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createDefaultBackgroundProtectionRepository,
  type BackgroundProtectionRecord,
} from "../../server/src/api/backgroundProtectionPersistence.js";
import type {
  CredentialReference,
  CredentialVault,
  CredentialVaultCapabilities,
} from "../../server/src/security/credentialVault.js";

const directories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-background-state-"));
  directories.push(directory);
  return directory;
}

class TestVault implements CredentialVault {
  readonly values = new Map<string, string>();
  readonly writes: Array<{ reference: CredentialReference; secret: string }> = [];
  failWrite = false;

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
    if (this.failWrite) throw new Error("simulated vault failure");
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

function scheduled(overrides: Partial<BackgroundProtectionRecord> = {}): BackgroundProtectionRecord {
  return {
    enabled: true,
    intervalMinutes: 60,
    nextRunAt: 1_800_000_000_000,
    lastAttemptAt: null,
    lastCompletedAt: null,
    status: "scheduled",
    consecutiveFailures: 0,
    lastErrorCode: null,
    ...overrides,
  };
}

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("protected background protection persistence", () => {
  it("encrypts account schedules under a separate native-vault key and recovers interrupted work", async () => {
    const directory = temporaryDirectory();
    const vault = new TestVault();
    const repository = await createDefaultBackgroundProtectionRepository({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    });
    const accountKey = "a".repeat(64);
    repository.save(accountKey, scheduled({ status: "running" }));

    expect(repository.persistent).toBe(true);
    expect(vault.writes).toHaveLength(1);
    expect(vault.writes[0]?.reference).toMatchObject({
      id: expect.stringMatching(/^background-protection-encryption-key-v1:data:[a-f0-9]{64}$/),
      kind: "local-encryption-key",
    });
    expect(Buffer.from(vault.writes[0]!.secret, "base64")).toHaveLength(32);
    const path = join(directory, "background-protection.enc.json");
    const raw = readFileSync(path, "utf8");
    expect(raw).not.toContain(accountKey);
    expect(raw).not.toContain("intervalMinutes");

    const restarted = await createDefaultBackgroundProtectionRepository({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    });
    expect(restarted.get(accountKey)).toMatchObject({
      status: "failed",
      lastErrorCode: "protected_state_failure",
      consecutiveFailures: 1,
    });
    expect(vault.writes).toHaveLength(1);
  });

  it("returns clones and rejects invalid intervals or unknown fields", async () => {
    const repository = await createDefaultBackgroundProtectionRepository({
      dataDirectory: temporaryDirectory(),
      credentialVault: new TestVault(false),
      platform: "linux",
    });
    const accountKey = "b".repeat(64);
    repository.save(accountKey, scheduled());
    const first = repository.get(accountKey)!;
    first.intervalMinutes = 30;
    expect(repository.get(accountKey)?.intervalMinutes).toBe(60);
    expect(() => repository.save(accountKey, scheduled({ intervalMinutes: 29 }))).toThrow(/quota range/i);
    expect(() => repository.save(accountKey, { ...scheduled(), mailbox: "user@example.test" } as BackgroundProtectionRecord)).toThrow(/unknown fields/i);
  });

  it("uses memory only on a fresh unsupported platform and fails closed if encrypted state already exists", async () => {
    const directory = temporaryDirectory();
    const memory = await createDefaultBackgroundProtectionRepository({
      dataDirectory: directory,
      credentialVault: new TestVault(false),
      platform: "linux",
    });
    memory.save("c".repeat(64), scheduled());
    expect(memory.persistent).toBe(false);
    expect(existsSync(join(directory, "background-protection.enc.json"))).toBe(false);

    writeFileSync(join(directory, "background-protection.enc.json"), "encrypted-state-must-not-be-reset");
    await expect(createDefaultBackgroundProtectionRepository({
      dataDirectory: directory,
      credentialVault: new TestVault(false),
      platform: "linux",
    })).rejects.toThrow(/protected key is unavailable/i);
  });

  it("does not create state if native key custody fails", async () => {
    const directory = temporaryDirectory();
    const vault = new TestVault();
    vault.failWrite = true;
    await expect(createDefaultBackgroundProtectionRepository({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    })).rejects.toThrow(/vault failure/i);
    expect(existsSync(join(directory, "background-protection.enc.json"))).toBe(false);
  });

  it("preserves and rejects authenticated state after ciphertext tampering", async () => {
    const directory = temporaryDirectory();
    const vault = new TestVault();
    const repository = await createDefaultBackgroundProtectionRepository({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    });
    repository.save("d".repeat(64), scheduled());
    const path = join(directory, "background-protection.enc.json");
    const envelope = JSON.parse(readFileSync(path, "utf8")) as { ciphertext: string };
    envelope.ciphertext = `${envelope.ciphertext[0] === "A" ? "B" : "A"}${envelope.ciphertext.slice(1)}`;
    writeFileSync(path, JSON.stringify(envelope));

    await expect(createDefaultBackgroundProtectionRepository({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    })).rejects.toThrow(/cannot be authenticated with its data-bound or legacy key/i);
    expect(existsSync(path)).toBe(true);
  });
});
