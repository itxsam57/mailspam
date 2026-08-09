import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { CredentialReference, CredentialVault } from "../security/credentialVault.js";
import { createCredentialVault } from "../security/credentialVaultFactory.js";
import {
  applyRelationshipObservationToSnapshot,
  cloneRelationshipProfile,
  type RelationshipHistoryWorkerSnapshot,
  type RelationshipObservation,
  type RelationshipProfile,
} from "../engine/relationshipHistory.js";

const DATABASE_VERSION = 1;
const ALGORITHM = "aes-256-gcm";
const AAD = Buffer.from("email-shield-relationship-history-v1", "utf8");
const KEY_BYTES = 32;
const MAX_RELATIONSHIPS_PER_ACCOUNT = 20_000;
const MAX_OBSERVED_MESSAGES_PER_ACCOUNT = 100_000;
const MAX_REPLY_TO_KEYS = 8;
const MAX_DATABASE_BYTES = 32 * 1024 * 1024;
const KEY_REFERENCE: CredentialReference = {
  id: "relationship-history-encryption-key-v1",
  kind: "local-encryption-key",
};

interface RelationshipAccountState {
  records: Record<string, RelationshipProfile>;
  /** HMAC message keys with local observation time; used only for idempotent replay protection. */
  observedMessages: Record<string, number>;
}

interface RelationshipHistoryDatabase {
  version: 1;
  accounts: Record<string, RelationshipAccountState>;
}

interface EncryptedRelationshipEnvelope {
  version: 1;
  algorithm: "aes-256-gcm";
  iv: string;
  authTag: string;
  ciphertext: string;
}

export interface RelationshipHistoryRepository {
  readonly persistent: boolean;
  workerSnapshot(accountKey: string): RelationshipHistoryWorkerSnapshot;
  merge(accountKey: string, observations: RelationshipObservation[]): void;
}

export interface RelationshipHistoryRepositoryFactoryOptions {
  dataDirectory?: string;
  credentialVault?: CredentialVault;
  platform?: NodeJS.Platform;
}

interface RelationshipCapacity {
  maxRelationships: number;
  maxObservedMessages: number;
}

const DEFAULT_CAPACITY: RelationshipCapacity = {
  maxRelationships: MAX_RELATIONSHIPS_PER_ACCOUNT,
  maxObservedMessages: MAX_OBSERVED_MESSAGES_PER_ACCOUNT,
};

function defaultDataDirectory(): string {
  return process.env.EMAIL_SHIELD_DATA_DIR?.trim() || join(homedir(), ".email-shield");
}

function validAccountKey(value: string): boolean {
  return /^[a-f0-9]{64}$/.test(value);
}

function validFingerprint(value: string): boolean {
  return /^[a-f0-9]{64}$/.test(value);
}

function boundedInteger(value: unknown): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(Number.MAX_SAFE_INTEGER, Math.max(0, Math.floor(Number(value))));
}

function sanitizeCountMap(input: unknown, maxEntries: number): Record<string, number> {
  if (!input || typeof input !== "object" || Array.isArray(input)) return {};
  const entries = Object.entries(input as Record<string, unknown>)
    .filter(([key, value]) => validFingerprint(key) && boundedInteger(value) > 0)
    .map(([key, value]) => [key, boundedInteger(value)] as const)
    .sort((left, right) => right[1] - left[1])
    .slice(0, maxEntries);
  return Object.fromEntries(entries);
}

function sanitizeFolderCounts(input: unknown): RelationshipProfile["folderCounts"] {
  if (!input || typeof input !== "object" || Array.isArray(input)) return {};
  const allowed = new Set(["inbox", "spam", "sent", "drafts", "trash", "archive", "other"]);
  const output: RelationshipProfile["folderCounts"] = {};
  for (const [folder, rawCount] of Object.entries(input as Record<string, unknown>)) {
    if (!allowed.has(folder)) continue;
    const count = boundedInteger(rawCount);
    if (count > 0) output[folder as "inbox" | "spam" | "sent" | "drafts" | "trash" | "archive" | "other"] = count;
  }
  return output;
}

function sanitizeProfile(input: unknown): RelationshipProfile | null {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const value = input as Record<string, unknown>;
  const firstObservedAt = boundedInteger(value.firstObservedAt);
  const lastObservedAt = boundedInteger(value.lastObservedAt);
  if (!firstObservedAt || !lastObservedAt || firstObservedAt > lastObservedAt) return null;
  const lastAuthenticatedAt = value.lastAuthenticatedAt === null
    ? null
    : boundedInteger(value.lastAuthenticatedAt);
  return {
    messagesSeen: boundedInteger(value.messagesSeen),
    authenticatedMessages: boundedInteger(value.authenticatedMessages),
    safeMessages: boundedInteger(value.safeMessages),
    reviewMessages: boundedInteger(value.reviewMessages),
    highRiskMessages: boundedInteger(value.highRiskMessages),
    confirmedThreatMessages: boundedInteger(value.confirmedThreatMessages),
    unknownMessages: boundedInteger(value.unknownMessages),
    firstObservedAt,
    lastObservedAt,
    lastAuthenticatedAt: lastAuthenticatedAt || null,
    folderCounts: sanitizeFolderCounts(value.folderCounts),
    replyToCounts: sanitizeCountMap(value.replyToCounts, MAX_REPLY_TO_KEYS),
  };
}

function sanitizeObservation(input: RelationshipObservation): RelationshipObservation | null {
  if (!validFingerprint(input.senderKey) || !validFingerprint(input.messageKey)) return null;
  if (input.replyToKey !== null && !validFingerprint(input.replyToKey)) return null;
  if (!["inbox", "spam", "sent", "drafts", "trash", "archive", "other"].includes(input.folder)) return null;
  if (!["safe", "review", "high_risk", "confirmed_threat", "unknown"].includes(input.verdict)) return null;
  const observedAt = boundedInteger(input.observedAt);
  if (!observedAt) return null;
  return {
    senderKey: input.senderKey,
    messageKey: input.messageKey,
    replyToKey: input.replyToKey,
    observedAt,
    folder: input.folder,
    authenticated: input.authenticated === true,
    verdict: input.verdict,
  };
}

function pruneAccount(
  state: RelationshipAccountState,
  capacity: RelationshipCapacity = DEFAULT_CAPACITY,
): RelationshipAccountState {
  const records = Object.fromEntries(
    Object.entries(state.records)
      .filter(([key, value]) => validFingerprint(key) && Boolean(sanitizeProfile(value)))
      .sort((left, right) => right[1].lastObservedAt - left[1].lastObservedAt)
      .slice(0, capacity.maxRelationships)
      .map(([key, value]) => [key, cloneRelationshipProfile(value)]),
  );

  // Replay fingerprints are deliberately not rotated by recency. Evicting an
  // old key would let a later Full scan count that same message again. Once the
  // exact index reaches capacity, mergeIntoState conservatively stops learning
  // new observations instead of corrupting existing relationship counts.
  const observedMessages = Object.fromEntries(
    Object.entries(state.observedMessages)
      .filter(([key, value]) => validFingerprint(key) && boundedInteger(value) > 0)
      .slice(0, capacity.maxObservedMessages)
      .map(([key, value]) => [key, boundedInteger(value)]),
  );
  return { records, observedMessages };
}

function cloneAccountState(state: RelationshipAccountState): RelationshipAccountState {
  return {
    records: Object.fromEntries(Object.entries(state.records).map(([key, value]) => [key, cloneRelationshipProfile(value)])),
    observedMessages: { ...state.observedMessages },
  };
}

function deriveMasterIndexKey(encryptionKey: Buffer): Buffer {
  return createHmac("sha256", encryptionKey)
    .update("email-shield-relationship-index-key-v1", "utf8")
    .digest();
}

function deriveAccountIndexKey(masterIndexKey: Buffer, accountKey: string): Buffer {
  if (!validAccountKey(accountKey)) throw new Error("Relationship-history account key is invalid.");
  return createHmac("sha256", masterIndexKey)
    .update("email-shield-relationship-account-index-v1\0", "utf8")
    .update(accountKey, "utf8")
    .digest();
}

function emptyState(): RelationshipAccountState {
  return { records: {}, observedMessages: {} };
}

function snapshotForState(state: RelationshipAccountState, accountIndexKey: Buffer): RelationshipHistoryWorkerSnapshot {
  return {
    indexKey: accountIndexKey.toString("base64"),
    records: Object.fromEntries(Object.entries(state.records).map(([key, value]) => [key, cloneRelationshipProfile(value)])),
    seenMessageKeys: new Set(Object.keys(state.observedMessages)),
  };
}

function mergeIntoState(
  state: RelationshipAccountState,
  accountIndexKey: Buffer,
  observations: RelationshipObservation[],
  capacity: RelationshipCapacity = DEFAULT_CAPACITY,
): RelationshipAccountState {
  const next = cloneAccountState(state);
  const snapshot = snapshotForState(next, accountIndexKey);

  for (const rawObservation of observations) {
    const observation = sanitizeObservation(rawObservation);
    if (!observation) continue;
    if (snapshot.seenMessageKeys.has(observation.messageKey)) continue;

    // Never recycle an old replay key. At hard capacity, relationship learning
    // freezes for unseen messages so repeated scans remain idempotent.
    if (snapshot.seenMessageKeys.size >= capacity.maxObservedMessages) continue;
    if (!snapshot.records[observation.senderKey]
      && Object.keys(snapshot.records).length >= capacity.maxRelationships) continue;

    if (applyRelationshipObservationToSnapshot(snapshot, observation)) {
      next.observedMessages[observation.messageKey] = observation.observedAt;
    }
  }
  next.records = snapshot.records;
  return pruneAccount(next, capacity);
}

export class InMemoryRelationshipHistoryRepository implements RelationshipHistoryRepository {
  readonly persistent = false;
  private readonly accounts = new Map<string, RelationshipAccountState>();
  private readonly masterIndexKey: Buffer;
  private readonly capacity: RelationshipCapacity;

  constructor(
    masterIndexKey = randomBytes(KEY_BYTES),
    capacity: Partial<RelationshipCapacity> = {},
  ) {
    if (!Buffer.isBuffer(masterIndexKey) || masterIndexKey.length !== KEY_BYTES) throw new Error("Relationship-history index key is invalid.");
    this.masterIndexKey = Buffer.from(masterIndexKey);
    this.capacity = {
      maxRelationships: Math.max(1, Math.floor(capacity.maxRelationships ?? MAX_RELATIONSHIPS_PER_ACCOUNT)),
      maxObservedMessages: Math.max(1, Math.floor(capacity.maxObservedMessages ?? MAX_OBSERVED_MESSAGES_PER_ACCOUNT)),
    };
  }

  workerSnapshot(accountKey: string): RelationshipHistoryWorkerSnapshot {
    if (!validAccountKey(accountKey)) throw new Error("Relationship-history account key is invalid.");
    return snapshotForState(
      this.accounts.get(accountKey) ?? emptyState(),
      deriveAccountIndexKey(this.masterIndexKey, accountKey),
    );
  }

  merge(accountKey: string, observations: RelationshipObservation[]): void {
    if (!validAccountKey(accountKey)) throw new Error("Relationship-history account key is invalid.");
    this.accounts.set(
      accountKey,
      mergeIntoState(
        this.accounts.get(accountKey) ?? emptyState(),
        deriveAccountIndexKey(this.masterIndexKey, accountKey),
        observations,
        this.capacity,
      ),
    );
  }
}

export class EncryptedFileRelationshipHistoryRepository implements RelationshipHistoryRepository {
  readonly persistent = true;
  private readonly databasePath: string;
  private readonly encryptionKey: Buffer;
  private readonly masterIndexKey: Buffer;

  constructor(readonly dataDirectory: string, encryptionKey: Buffer) {
    if (!Buffer.isBuffer(encryptionKey) || encryptionKey.length !== KEY_BYTES) {
      throw new Error("Local relationship-history encryption key is invalid.");
    }
    this.databasePath = join(dataDirectory, "relationship-history.enc.json");
    this.encryptionKey = Buffer.from(encryptionKey);
    this.masterIndexKey = deriveMasterIndexKey(this.encryptionKey);
  }

  workerSnapshot(accountKey: string): RelationshipHistoryWorkerSnapshot {
    if (!validAccountKey(accountKey)) throw new Error("Relationship-history account key is invalid.");
    return snapshotForState(
      this.readDatabase().accounts[accountKey] ?? emptyState(),
      deriveAccountIndexKey(this.masterIndexKey, accountKey),
    );
  }

  merge(accountKey: string, observations: RelationshipObservation[]): void {
    if (!validAccountKey(accountKey)) throw new Error("Relationship-history account key is invalid.");
    if (!Array.isArray(observations) || observations.length === 0) return;
    const database = this.readDatabase();
    const current = database.accounts[accountKey] ?? emptyState();
    database.accounts[accountKey] = mergeIntoState(
      current,
      deriveAccountIndexKey(this.masterIndexKey, accountKey),
      observations,
    );
    this.writeDatabase(database);
  }

  assertReadable(): void {
    void this.readDatabase();
  }

  private ensureDirectory(): void {
    mkdirSync(this.dataDirectory, { recursive: true, mode: 0o700 });
    try { chmodSync(this.dataDirectory, 0o700); } catch {}
  }

  private readDatabase(): RelationshipHistoryDatabase {
    if (!existsSync(this.databasePath)) return { version: DATABASE_VERSION, accounts: {} };
    try {
      const raw = readFileSync(this.databasePath);
      if (raw.length > MAX_DATABASE_BYTES) throw new Error("Encrypted relationship-history file exceeds the local size limit.");
      const envelope = JSON.parse(raw.toString("utf8")) as Partial<EncryptedRelationshipEnvelope>;
      if (
        envelope.version !== DATABASE_VERSION ||
        envelope.algorithm !== ALGORITHM ||
        typeof envelope.iv !== "string" ||
        typeof envelope.authTag !== "string" ||
        typeof envelope.ciphertext !== "string"
      ) throw new Error("Unsupported encrypted relationship-history format.");

      const decipher = createDecipheriv(ALGORITHM, this.encryptionKey, Buffer.from(envelope.iv, "base64"));
      decipher.setAAD(AAD);
      decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, "base64")),
        decipher.final(),
      ]).toString("utf8");
      const parsed = JSON.parse(plaintext) as Partial<RelationshipHistoryDatabase>;
      if (parsed.version !== DATABASE_VERSION || !parsed.accounts || typeof parsed.accounts !== "object") {
        throw new Error("Unsupported relationship-history database format.");
      }

      const accounts: Record<string, RelationshipAccountState> = {};
      for (const [accountKey, rawState] of Object.entries(parsed.accounts)) {
        if (!validAccountKey(accountKey) || !rawState || typeof rawState !== "object" || Array.isArray(rawState)) continue;
        const state = rawState as Partial<RelationshipAccountState>;
        const records: Record<string, RelationshipProfile> = {};
        if (state.records && typeof state.records === "object" && !Array.isArray(state.records)) {
          for (const [key, rawProfile] of Object.entries(state.records)) {
            const profile = sanitizeProfile(rawProfile);
            if (validFingerprint(key) && profile) records[key] = profile;
          }
        }
        const observedMessages: Record<string, number> = {};
        if (state.observedMessages && typeof state.observedMessages === "object" && !Array.isArray(state.observedMessages)) {
          for (const [key, rawTimestamp] of Object.entries(state.observedMessages)) {
            const timestamp = boundedInteger(rawTimestamp);
            if (validFingerprint(key) && timestamp) observedMessages[key] = timestamp;
          }
        }
        accounts[accountKey] = pruneAccount({ records, observedMessages });
      }
      return { version: DATABASE_VERSION, accounts };
    } catch (error) {
      throw new Error(`Encrypted local relationship history could not be read: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private writeDatabase(database: RelationshipHistoryDatabase): void {
    this.ensureDirectory();
    const plaintext = JSON.stringify(database);
    if (Buffer.byteLength(plaintext, "utf8") > MAX_DATABASE_BYTES) {
      throw new Error("Relationship-history database exceeds the local size limit.");
    }
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGORITHM, this.encryptionKey, iv);
    cipher.setAAD(AAD);
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const envelope: EncryptedRelationshipEnvelope = {
      version: DATABASE_VERSION,
      algorithm: ALGORITHM,
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
    const temporaryPath = `${this.databasePath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
    writeFileSync(temporaryPath, JSON.stringify(envelope), { mode: 0o600 });
    try {
      renameSync(temporaryPath, this.databasePath);
    } catch {
      rmSync(this.databasePath, { force: true });
      renameSync(temporaryPath, this.databasePath);
    }
    try { chmodSync(this.databasePath, 0o600); } catch {}
  }
}

function encodeKey(key: Buffer): string {
  return key.toString("base64");
}

function decodeKey(secret: string): Buffer {
  const normalized = secret.trim();
  const key = Buffer.from(normalized, "base64");
  if (key.length !== KEY_BYTES || key.toString("base64") !== normalized) {
    throw new Error("Protected relationship-history encryption key is invalid.");
  }
  return key;
}

function sameKey(left: Buffer, right: Buffer): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

async function writeAndVerifyKey(vault: CredentialVault, key: Buffer): Promise<void> {
  await vault.write(KEY_REFERENCE, encodeKey(key));
  const stored = await vault.read(KEY_REFERENCE);
  if (!stored) throw new Error("Protected relationship-history encryption key write was not readable.");
  const roundTrip = decodeKey(stored);
  if (!sameKey(key, roundTrip)) throw new Error("Protected relationship-history encryption key verification failed.");
}

export async function createDefaultRelationshipHistoryRepository(
  options: RelationshipHistoryRepositoryFactoryOptions = {},
): Promise<RelationshipHistoryRepository> {
  const dataDirectory = options.dataDirectory ?? defaultDataDirectory();
  const databasePath = join(dataDirectory, "relationship-history.enc.json");
  const platform = options.platform ?? process.platform;
  const vault = options.credentialVault ?? createCredentialVault(platform);
  const databaseExists = existsSync(databasePath);

  if (!vault.capabilities().available) {
    if (databaseExists) {
      throw new Error("Encrypted relationship history exists but its protected encryption key is unavailable on this platform.");
    }
    return new InMemoryRelationshipHistoryRepository();
  }

  const protectedSecret = await vault.read(KEY_REFERENCE);
  let key: Buffer;
  if (protectedSecret) {
    key = decodeKey(protectedSecret);
  } else {
    if (databaseExists) {
      throw new Error("Encrypted relationship history exists but its protected encryption key is unavailable.");
    }
    key = randomBytes(KEY_BYTES);
    await writeAndVerifyKey(vault, key);
  }

  const repository = new EncryptedFileRelationshipHistoryRepository(dataDirectory, key);
  repository.assertReadable();
  return repository;
}
