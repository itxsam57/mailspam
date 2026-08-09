import { afterEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createDefaultScanStateRepository,
  type ScanHistoryRecord,
} from "../../server/src/api/scanStatePersistence.js";
import type {
  CredentialReference,
  CredentialVault,
  CredentialVaultCapabilities,
} from "../../server/src/security/credentialVault.js";

const directories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-scan-state-"));
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
    if (this.failWrite) throw new Error("simulated protected-store failure");
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

function record(status: ScanHistoryRecord["status"] = "running"): ScanHistoryRecord {
  return {
    scanId: "123e4567-e89b-42d3-a456-426614174000",
    type: "full",
    status,
    startedAt: 1_700_000_000_000,
    updatedAt: 1_700_000_000_500,
    completedAt: status === "completed" ? 1_700_000_001_000 : null,
    counters: {
      examined: 20,
      safe: 15,
      review: 2,
      highRisk: 2,
      confirmedThreat: 1,
      unknown: 0,
      skipped: 0,
      malformed: 0,
    },
    checkpoint: status === "completed" ? null : {
      currentCursor: null,
      folderCursors: { INBOX: "provider-secret-page-token-abc123" },
      completedFolders: ["JUNK"],
      seenSenderHashes: ["a".repeat(64)],
      seenMessageHashes: ["b".repeat(64)],
    },
  };
}

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("encrypted resumable scan-state persistence", () => {
  it("stores scan checkpoints under a separate native-vault key and keeps provider cursors out of plaintext files", async () => {
    const directory = temporaryDirectory();
    const vault = new TestVault();
    const repository = await createDefaultScanStateRepository({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    });
    const accountKey = "1".repeat(64);
    repository.save(accountKey, record());

    expect(repository.persistent).toBe(true);
    expect(vault.writes).toHaveLength(1);
    expect(vault.writes[0]?.reference).toEqual({
      id: "scan-history-encryption-key-v1",
      kind: "local-encryption-key",
    });
    expect(Buffer.from(vault.writes[0]!.secret, "base64")).toHaveLength(32);
    expect(existsSync(join(directory, "scan-state.enc.json"))).toBe(true);
    expect(existsSync(join(directory, "scan-history.key"))).toBe(false);

    const raw = readFileSync(join(directory, "scan-state.enc.json"), "utf8");
    expect(raw).not.toContain("provider-secret-page-token-abc123");
    expect(raw).not.toContain("INBOX");
    expect(raw).not.toContain("JUNK");

    const restarted = await createDefaultScanStateRepository({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    });
    const recovered = restarted.get(accountKey, record().scanId);
    expect(recovered?.status).toBe("interrupted");
    expect(recovered?.checkpoint?.folderCursors.INBOX).toBe("provider-secret-page-token-abc123");
    expect(vault.writes).toHaveLength(1);
  });

  it("does not expose mutable repository internals through returned history records", async () => {
    const repository = await createDefaultScanStateRepository({
      dataDirectory: temporaryDirectory(),
      credentialVault: new TestVault(false),
      platform: "linux",
    });
    const accountKey = "2".repeat(64);
    repository.save(accountKey, record("failed"));
    const first = repository.list(accountKey);
    first[0]!.counters.examined = 999;
    first[0]!.checkpoint!.folderCursors.INBOX = "tampered";

    const second = repository.list(accountKey);
    expect(second[0]?.counters.examined).toBe(20);
    expect(second[0]?.checkpoint?.folderCursors.INBOX).toBe("provider-secret-page-token-abc123");
  });

  it("uses memory-only history on a fresh machine when the expected native vault is unavailable", async () => {
    const directory = temporaryDirectory();
    const repository = await createDefaultScanStateRepository({
      dataDirectory: directory,
      credentialVault: new TestVault(false),
      platform: "linux",
    });
    repository.save("3".repeat(64), record("stopped"));

    expect(repository.persistent).toBe(false);
    expect(existsSync(join(directory, "scan-state.enc.json"))).toBe(false);
  });

  it("fails closed when encrypted history exists but its native-vault key is unavailable", async () => {
    const directory = temporaryDirectory();
    const vault = new TestVault();
    const repository = await createDefaultScanStateRepository({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    });
    repository.save("4".repeat(64), record("failed"));

    await expect(createDefaultScanStateRepository({
      dataDirectory: directory,
      credentialVault: new TestVault(false),
      platform: "linux",
    })).rejects.toThrow(/encrypted scan history exists/i);
    expect(existsSync(join(directory, "scan-state.enc.json"))).toBe(true);
  });

  it("does not create an encrypted database when the first protected key write fails", async () => {
    const directory = temporaryDirectory();
    const vault = new TestVault();
    vault.failWrite = true;

    await expect(createDefaultScanStateRepository({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    })).rejects.toThrow();
    expect(existsSync(join(directory, "scan-state.enc.json"))).toBe(false);
  });

  it("drops resume checkpoints from completed history while retaining privacy-reduced counters", async () => {
    const repository = await createDefaultScanStateRepository({
      dataDirectory: temporaryDirectory(),
      credentialVault: new TestVault(false),
      platform: "linux",
    });
    const accountKey = "5".repeat(64);
    repository.save(accountKey, record("completed"));
    const saved = repository.get(accountKey, record().scanId);
    expect(saved?.status).toBe("completed");
    expect(saved?.checkpoint).toBeNull();
    expect(saved?.counters).toMatchObject({ examined: 20, confirmedThreat: 1 });
  });
});
