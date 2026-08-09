import { afterEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CredentialReference, CredentialVault, CredentialVaultCapabilities } from "../../server/src/security/credentialVault.js";
import {
  createDefaultRelationshipHistoryRepository,
  EncryptedFileRelationshipHistoryRepository,
  InMemoryRelationshipHistoryRepository,
} from "../../server/src/api/relationshipHistoryPersistence.js";
import {
  relationshipIdentityKey,
  type RelationshipObservation,
} from "../../server/src/engine/relationshipHistory.js";

const temporaryDirectories: string[] = [];
const ACCOUNT_A = "a".repeat(64);
const ACCOUNT_B = "b".repeat(64);

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-relationship-"));
  temporaryDirectories.push(directory);
  return directory;
}

class TestVault implements CredentialVault {
  readonly values = new Map<string, string>();
  readonly writes: Array<{ reference: CredentialReference; secret: string }> = [];

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

function observationFor(
  repository: InMemoryRelationshipHistoryRepository | EncryptedFileRelationshipHistoryRepository,
  accountKey: string,
  params: { sender: string; message: string; observedAt?: number },
): RelationshipObservation {
  const snapshot = repository.workerSnapshot(accountKey);
  return {
    senderKey: relationshipIdentityKey(snapshot.indexKey, "sender", params.sender),
    messageKey: relationshipIdentityKey(snapshot.indexKey, "message", params.message),
    replyToKey: null,
    observedAt: params.observedAt ?? 1_700_000_000_000,
    folder: "inbox",
    authenticated: true,
    verdict: "safe",
  };
}

function profileFor(
  repository: InMemoryRelationshipHistoryRepository | EncryptedFileRelationshipHistoryRepository,
  accountKey: string,
  sender: string,
) {
  const snapshot = repository.workerSnapshot(accountKey);
  const senderKey = relationshipIdentityKey(snapshot.indexKey, "sender", sender);
  return snapshot.records[senderKey];
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("encrypted relationship history", () => {
  it("uses account-scoped HMAC fingerprints so the same sender cannot be correlated across accounts", () => {
    const repository = new InMemoryRelationshipHistoryRepository(Buffer.alloc(32, 7));
    const sender = "known.sender@example.com";
    const keyA = relationshipIdentityKey(repository.workerSnapshot(ACCOUNT_A).indexKey, "sender", sender);
    const keyB = relationshipIdentityKey(repository.workerSnapshot(ACCOUNT_B).indexKey, "sender", sender);

    expect(keyA).toMatch(/^[a-f0-9]{64}$/);
    expect(keyB).toMatch(/^[a-f0-9]{64}$/);
    expect(keyA).not.toBe(keyB);
    expect(keyA).not.toContain("known.sender");
  });

  it("counts the same message fingerprint only once across repeated merges", () => {
    const repository = new InMemoryRelationshipHistoryRepository(Buffer.alloc(32, 8));
    const sender = "repeat@example.com";
    const observation = observationFor(repository, ACCOUNT_A, { sender, message: "<same-message@example.com>" });

    repository.merge(ACCOUNT_A, [observation]);
    repository.merge(ACCOUNT_A, [observation]);

    expect(profileFor(repository, ACCOUNT_A, sender)).toMatchObject({
      messagesSeen: 1,
      authenticatedMessages: 1,
      safeMessages: 1,
    });
    expect(repository.workerSnapshot(ACCOUNT_A).seenMessageKeys.size).toBe(1);
  });

  it("encrypts history at rest without plaintext sender or raw message identity", () => {
    const directory = temporaryDirectory();
    const repository = new EncryptedFileRelationshipHistoryRepository(directory, Buffer.alloc(32, 9));
    const sender = "private.person@example.com";
    const rawMessageIdentity = "<private-message-123@example.com>";
    repository.merge(ACCOUNT_A, [observationFor(repository, ACCOUNT_A, {
      sender,
      message: rawMessageIdentity,
    })]);

    const path = join(directory, "relationship-history.enc.json");
    const raw = readFileSync(path, "utf8");
    expect(raw).toContain('"algorithm":"aes-256-gcm"');
    expect(raw).not.toContain(sender);
    expect(raw).not.toContain(rawMessageIdentity);
    expect(raw).not.toContain("private.person");
    expect(profileFor(repository, ACCOUNT_A, sender)?.messagesSeen).toBe(1);
  });

  it("stores a separate protected local-encryption-key and survives repository restart", async () => {
    const directory = temporaryDirectory();
    const vault = new TestVault();
    const first = await createDefaultRelationshipHistoryRepository({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    });
    expect(first.persistent).toBe(true);
    expect(vault.writes).toHaveLength(1);
    expect(vault.writes[0]?.reference).toEqual({
      id: "relationship-history-encryption-key-v1",
      kind: "local-encryption-key",
    });

    const sender = "restart@example.com";
    const snapshot = first.workerSnapshot(ACCOUNT_A);
    const observation: RelationshipObservation = {
      senderKey: relationshipIdentityKey(snapshot.indexKey, "sender", sender),
      messageKey: relationshipIdentityKey(snapshot.indexKey, "message", "<restart-message@example.com>"),
      replyToKey: null,
      observedAt: 1_700_000_000_001,
      folder: "inbox",
      authenticated: true,
      verdict: "safe",
    };
    first.merge(ACCOUNT_A, [observation]);

    const restarted = await createDefaultRelationshipHistoryRepository({
      dataDirectory: directory,
      credentialVault: vault,
      platform: "win32",
    });
    const restartedSnapshot = restarted.workerSnapshot(ACCOUNT_A);
    const senderKey = relationshipIdentityKey(restartedSnapshot.indexKey, "sender", sender);
    expect(restartedSnapshot.records[senderKey]?.messagesSeen).toBe(1);
    expect(vault.writes).toHaveLength(1);
  });

  it("fails closed when encrypted relationship history exists but its native-vault key is unavailable", async () => {
    const directory = temporaryDirectory();
    const repository = new EncryptedFileRelationshipHistoryRepository(directory, Buffer.alloc(32, 10));
    repository.merge(ACCOUNT_A, [observationFor(repository, ACCOUNT_A, {
      sender: "locked@example.com",
      message: "<locked-message@example.com>",
    })]);

    await expect(createDefaultRelationshipHistoryRepository({
      dataDirectory: directory,
      credentialVault: new TestVault(false),
      platform: "linux",
    })).rejects.toThrow(/protected encryption key is unavailable/i);
  });

  it("uses memory-only history on a fresh unsupported platform without creating plaintext key or database files", async () => {
    const directory = temporaryDirectory();
    const repository = await createDefaultRelationshipHistoryRepository({
      dataDirectory: directory,
      credentialVault: new TestVault(false),
      platform: "linux",
    });

    expect(repository.persistent).toBe(false);
    expect(existsSync(join(directory, "relationship-history.enc.json"))).toBe(false);
    expect(existsSync(join(directory, "relationship-history.key"))).toBe(false);
  });
});
