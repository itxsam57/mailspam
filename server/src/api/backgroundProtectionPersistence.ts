import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { CredentialReference, CredentialVault } from "../security/credentialVault.js";
import { createCredentialVault } from "../security/credentialVaultFactory.js";
import {
  encryptedJsonEnvelopeByteCeiling,
  readBoundedRegularFile,
  replaceFileFromTemporaryPath,
} from "../util/localFileIntegrity.js";

const DATABASE_VERSION = 1;
const ALGORITHM = "aes-256-gcm";
const AAD = Buffer.from("email-shield-background-protection-v1", "utf8");
const KEY_BYTES = 32;
const MAX_DATABASE_BYTES = 256 * 1024;
const MAX_ENCRYPTED_DATABASE_BYTES = encryptedJsonEnvelopeByteCeiling(MAX_DATABASE_BYTES);
const MAX_ACCOUNTS = 128;
export const MIN_BACKGROUND_INTERVAL_MINUTES = 30;
export const MAX_BACKGROUND_INTERVAL_MINUTES = 24 * 60;

const KEY_REFERENCE: CredentialReference = {
  id: "background-protection-encryption-key-v1",
  kind: "local-encryption-key",
};

export type BackgroundProtectionStatus =
  | "paused"
  | "scheduled"
  | "running"
  | "completed"
  | "failed"
  | "deferred";

export type BackgroundProtectionErrorCode =
  | "provider_unavailable"
  | "scan_conflict"
  | "resource_deadline"
  | "protected_state_failure"
  | null;

export interface BackgroundProtectionRecord {
  enabled: boolean;
  intervalMinutes: number;
  nextRunAt: number | null;
  lastAttemptAt: number | null;
  lastCompletedAt: number | null;
  status: BackgroundProtectionStatus;
  consecutiveFailures: number;
  lastErrorCode: BackgroundProtectionErrorCode;
}

interface BackgroundProtectionDatabase {
  version: 1;
  accounts: Record<string, BackgroundProtectionRecord>;
}

interface EncryptedBackgroundProtectionEnvelope {
  version: 1;
  algorithm: "aes-256-gcm";
  iv: string;
  authTag: string;
  ciphertext: string;
}

export interface BackgroundProtectionRepository {
  readonly persistent: boolean;
  get(accountKey: string): BackgroundProtectionRecord | null;
  list(): Array<{ accountKey: string; record: BackgroundProtectionRecord }>;
  save(accountKey: string, record: BackgroundProtectionRecord): void;
  remove(accountKey: string): void;
  recoverInterrupted(now?: number): void;
}

export interface BackgroundProtectionRepositoryFactoryOptions {
  dataDirectory?: string;
  credentialVault?: CredentialVault;
  platform?: NodeJS.Platform;
}

function defaultDataDirectory(): string {
  return process.env.EMAIL_SHIELD_DATA_DIR?.trim() || join(homedir(), ".email-shield");
}

function validAccountKey(value: string): boolean {
  return /^[a-f0-9]{64}$/.test(value);
}

function validTimestamp(value: unknown, nullable: boolean): value is number | null {
  return (nullable && value === null) || (Number.isSafeInteger(value) && Number(value) > 0);
}

export function cloneBackgroundProtectionRecord(record: BackgroundProtectionRecord): BackgroundProtectionRecord {
  return { ...record };
}

export function assertBackgroundProtectionRecord(input: unknown): asserts input is BackgroundProtectionRecord {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("Background protection record must be an object.");
  }
  const value = input as Record<string, unknown>;
  const knownFields = new Set([
    "enabled",
    "intervalMinutes",
    "nextRunAt",
    "lastAttemptAt",
    "lastCompletedAt",
    "status",
    "consecutiveFailures",
    "lastErrorCode",
  ]);
  if (Object.keys(value).some((field) => !knownFields.has(field))) {
    throw new Error("Background protection record contains unknown fields.");
  }
  if (typeof value.enabled !== "boolean") throw new Error("Background protection enabled state is invalid.");
  if (
    !Number.isSafeInteger(value.intervalMinutes) ||
    Number(value.intervalMinutes) < MIN_BACKGROUND_INTERVAL_MINUTES ||
    Number(value.intervalMinutes) > MAX_BACKGROUND_INTERVAL_MINUTES
  ) throw new Error("Background protection interval is outside the accepted quota range.");
  if (!validTimestamp(value.nextRunAt, true) || !validTimestamp(value.lastAttemptAt, true) || !validTimestamp(value.lastCompletedAt, true)) {
    throw new Error("Background protection timestamps are invalid.");
  }
  if (!["paused", "scheduled", "running", "completed", "failed", "deferred"].includes(String(value.status))) {
    throw new Error("Background protection status is invalid.");
  }
  if (!Number.isSafeInteger(value.consecutiveFailures) || Number(value.consecutiveFailures) < 0 || Number(value.consecutiveFailures) > 16) {
    throw new Error("Background protection failure count is invalid.");
  }
  if (![null, "provider_unavailable", "scan_conflict", "resource_deadline", "protected_state_failure"].includes(value.lastErrorCode as never)) {
    throw new Error("Background protection error code is invalid.");
  }
  if (value.enabled && value.nextRunAt === null && value.status !== "running") {
    throw new Error("Enabled background protection must have a next run time.");
  }
  if (!value.enabled && (value.nextRunAt !== null || value.status !== "paused")) {
    throw new Error("Paused background protection must not retain an active run time.");
  }
}

function normalizeRecord(input: unknown): BackgroundProtectionRecord {
  assertBackgroundProtectionRecord(input);
  return cloneBackgroundProtectionRecord(input);
}

export class InMemoryBackgroundProtectionRepository implements BackgroundProtectionRepository {
  readonly persistent = false;
  private readonly accounts = new Map<string, BackgroundProtectionRecord>();

  get(accountKey: string): BackgroundProtectionRecord | null {
    if (!validAccountKey(accountKey)) throw new Error("Background protection account key is invalid.");
    const record = this.accounts.get(accountKey);
    return record ? cloneBackgroundProtectionRecord(record) : null;
  }

  list(): Array<{ accountKey: string; record: BackgroundProtectionRecord }> {
    return [...this.accounts.entries()]
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([accountKey, record]) => ({ accountKey, record: cloneBackgroundProtectionRecord(record) }));
  }

  save(accountKey: string, record: BackgroundProtectionRecord): void {
    if (!validAccountKey(accountKey)) throw new Error("Background protection account key is invalid.");
    const normalized = normalizeRecord(record);
    if (!this.accounts.has(accountKey) && this.accounts.size >= MAX_ACCOUNTS) {
      throw new Error("Background protection account capacity has been reached.");
    }
    this.accounts.set(accountKey, normalized);
  }

  remove(accountKey: string): void {
    if (!validAccountKey(accountKey)) throw new Error("Background protection account key is invalid.");
    this.accounts.delete(accountKey);
  }

  recoverInterrupted(now = Date.now()): void {
    for (const [accountKey, record] of this.accounts) {
      if (record.status !== "running") continue;
      this.accounts.set(accountKey, {
        ...record,
        status: "failed",
        nextRunAt: now + 5 * 60_000,
        consecutiveFailures: Math.min(16, record.consecutiveFailures + 1),
        lastErrorCode: "protected_state_failure",
      });
    }
  }
}

export class EncryptedFileBackgroundProtectionRepository implements BackgroundProtectionRepository {
  readonly persistent = true;
  private readonly databasePath: string;
  private readonly encryptionKey: Buffer;

  constructor(readonly dataDirectory: string, encryptionKey: Buffer) {
    if (!Buffer.isBuffer(encryptionKey) || encryptionKey.length !== KEY_BYTES) {
      throw new Error("Background protection encryption key is invalid.");
    }
    this.databasePath = join(dataDirectory, "background-protection.enc.json");
    this.encryptionKey = Buffer.from(encryptionKey);
  }

  get(accountKey: string): BackgroundProtectionRecord | null {
    if (!validAccountKey(accountKey)) throw new Error("Background protection account key is invalid.");
    const record = this.readDatabase().accounts[accountKey];
    return record ? cloneBackgroundProtectionRecord(record) : null;
  }

  list(): Array<{ accountKey: string; record: BackgroundProtectionRecord }> {
    return Object.entries(this.readDatabase().accounts)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
      .map(([accountKey, record]) => ({ accountKey, record: cloneBackgroundProtectionRecord(record) }));
  }

  save(accountKey: string, record: BackgroundProtectionRecord): void {
    if (!validAccountKey(accountKey)) throw new Error("Background protection account key is invalid.");
    const database = this.readDatabase();
    if (!(accountKey in database.accounts) && Object.keys(database.accounts).length >= MAX_ACCOUNTS) {
      throw new Error("Background protection account capacity has been reached.");
    }
    database.accounts[accountKey] = normalizeRecord(record);
    this.writeDatabase(database);
  }

  remove(accountKey: string): void {
    if (!validAccountKey(accountKey)) throw new Error("Background protection account key is invalid.");
    const database = this.readDatabase();
    if (!(accountKey in database.accounts)) return;
    delete database.accounts[accountKey];
    this.writeDatabase(database);
  }

  recoverInterrupted(now = Date.now()): void {
    const database = this.readDatabase();
    let changed = false;
    for (const [accountKey, record] of Object.entries(database.accounts)) {
      if (record.status !== "running") continue;
      changed = true;
      database.accounts[accountKey] = {
        ...record,
        status: "failed",
        nextRunAt: now + 5 * 60_000,
        consecutiveFailures: Math.min(16, record.consecutiveFailures + 1),
        lastErrorCode: "protected_state_failure",
      };
    }
    if (changed) this.writeDatabase(database);
  }

  assertReadable(): void {
    void this.readDatabase();
  }

  private readDatabase(): BackgroundProtectionDatabase {
    if (!existsSync(this.databasePath)) return { version: DATABASE_VERSION, accounts: {} };
    try {
      const raw = readBoundedRegularFile(this.databasePath, {
        description: "Encrypted background protection file",
        maxBytes: MAX_ENCRYPTED_DATABASE_BYTES,
      });
      const envelope = JSON.parse(raw.toString("utf8")) as Partial<EncryptedBackgroundProtectionEnvelope>;
      if (Object.keys(envelope).some((field) => !["version", "algorithm", "iv", "authTag", "ciphertext"].includes(field))) {
        throw new Error("Encrypted background protection envelope contains unknown fields.");
      }
      if (
        envelope.version !== DATABASE_VERSION ||
        envelope.algorithm !== ALGORITHM ||
        typeof envelope.iv !== "string" ||
        typeof envelope.authTag !== "string" ||
        typeof envelope.ciphertext !== "string"
      ) throw new Error("Unsupported encrypted background protection format.");
      const decipher = createDecipheriv(ALGORITHM, this.encryptionKey, Buffer.from(envelope.iv, "base64"));
      decipher.setAAD(AAD);
      decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, "base64")),
        decipher.final(),
      ]).toString("utf8");
      if (Buffer.byteLength(plaintext, "utf8") > MAX_DATABASE_BYTES) throw new Error("Background protection database exceeds its size limit.");
      const parsed = JSON.parse(plaintext) as Partial<BackgroundProtectionDatabase>;
      if (Object.keys(parsed).some((field) => !["version", "accounts"].includes(field))) {
        throw new Error("Background protection database contains unknown fields.");
      }
      if (parsed.version !== DATABASE_VERSION || !parsed.accounts || typeof parsed.accounts !== "object" || Array.isArray(parsed.accounts)) {
        throw new Error("Unsupported background protection database format.");
      }
      const entries = Object.entries(parsed.accounts);
      if (entries.length > MAX_ACCOUNTS) throw new Error("Background protection database exceeds its account limit.");
      const accounts: Record<string, BackgroundProtectionRecord> = {};
      for (const [accountKey, rawRecord] of entries) {
        if (!validAccountKey(accountKey)) throw new Error("Background protection database contains an invalid account key.");
        accounts[accountKey] = normalizeRecord(rawRecord);
      }
      return { version: DATABASE_VERSION, accounts };
    } catch (error) {
      throw new Error(`Encrypted background protection state could not be read: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private writeDatabase(database: BackgroundProtectionDatabase): void {
    mkdirSync(this.dataDirectory, { recursive: true, mode: 0o700 });
    try { chmodSync(this.dataDirectory, 0o700); } catch {}
    const plaintext = JSON.stringify(database);
    if (Buffer.byteLength(plaintext, "utf8") > MAX_DATABASE_BYTES) throw new Error("Background protection database exceeds its size limit.");
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGORITHM, this.encryptionKey, iv);
    cipher.setAAD(AAD);
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const envelope: EncryptedBackgroundProtectionEnvelope = {
      version: DATABASE_VERSION,
      algorithm: ALGORITHM,
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
    const serialized = JSON.stringify(envelope);
    if (Buffer.byteLength(serialized, "utf8") > MAX_ENCRYPTED_DATABASE_BYTES) throw new Error("Encrypted background protection file exceeds its size limit.");
    const temporaryPath = `${this.databasePath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
    writeFileSync(temporaryPath, serialized, { mode: 0o600 });
    replaceFileFromTemporaryPath(temporaryPath, this.databasePath);
    try { chmodSync(this.databasePath, 0o600); } catch {}
  }
}

function decodeKey(secret: string): Buffer {
  const normalized = secret.trim();
  const key = Buffer.from(normalized, "base64");
  if (key.length !== KEY_BYTES || key.toString("base64") !== normalized) throw new Error("Protected background protection key is invalid.");
  return key;
}

async function writeAndVerifyKey(vault: CredentialVault, key: Buffer): Promise<void> {
  await vault.write(KEY_REFERENCE, key.toString("base64"));
  const stored = await vault.read(KEY_REFERENCE);
  if (!stored) throw new Error("Protected background protection key write was not readable.");
  const roundTrip = decodeKey(stored);
  if (roundTrip.length !== key.length || !timingSafeEqual(roundTrip, key)) throw new Error("Protected background protection key verification failed.");
}

export async function createDefaultBackgroundProtectionRepository(
  options: BackgroundProtectionRepositoryFactoryOptions = {},
): Promise<BackgroundProtectionRepository> {
  const dataDirectory = options.dataDirectory ?? defaultDataDirectory();
  const databasePath = join(dataDirectory, "background-protection.enc.json");
  const platform = options.platform ?? process.platform;
  const vault = options.credentialVault ?? createCredentialVault(platform);
  const databaseExists = existsSync(databasePath);

  if (!vault.capabilities().available) {
    if (databaseExists) throw new Error("Encrypted background protection state exists but its protected key is unavailable on this platform.");
    return new InMemoryBackgroundProtectionRepository();
  }

  const stored = await vault.read(KEY_REFERENCE);
  let key: Buffer;
  if (stored) key = decodeKey(stored);
  else {
    if (databaseExists) throw new Error("Encrypted background protection state exists but its protected key is unavailable.");
    key = randomBytes(KEY_BYTES);
    await writeAndVerifyKey(vault, key);
  }

  const repository = new EncryptedFileBackgroundProtectionRepository(dataDirectory, key);
  repository.assertReadable();
  repository.recoverInterrupted();
  return repository;
}
