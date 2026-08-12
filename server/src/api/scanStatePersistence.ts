import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import type { CredentialReference, CredentialVault } from "../security/credentialVault.js";
import { encryptedJsonEnvelopeByteCeiling, readBoundedRegularFile, replaceFileFromTemporaryPath } from "../util/localFileIntegrity.js";
import { createCredentialVault } from "../security/credentialVaultFactory.js";
import { resolveDataBoundEncryptionKey } from "../security/dataBoundEncryptionKey.js";
import { defaultEmailShieldDataDirectory } from "../security/dataDirectory.js";
import type { ScanCounters } from "../workflows/scanWorkflows.js";

const DATABASE_VERSION = 1;
const ALGORITHM = "aes-256-gcm";
const AAD = Buffer.from("email-shield-scan-state-v1", "utf8");
const KEY_BYTES = 32;
const MAX_HISTORY_PER_ACCOUNT = 40;
const MAX_CURSOR_BYTES = 16 * 1024;
const MAX_HASHES = 50_000;
const MAX_COMPLETED_FOLDERS = 256;
const MAX_DATABASE_BYTES = 8 * 1024 * 1024;
export const SCAN_STATE_ENCRYPTED_DATABASE_MAX_BYTES = encryptedJsonEnvelopeByteCeiling(MAX_DATABASE_BYTES);
const KEY_REFERENCE: CredentialReference = {
  id: "scan-history-encryption-key-v1",
  kind: "local-encryption-key",
};

export type ScanType = "quick" | "full" | "spam";
export type ScanHistoryStatus = "running" | "interrupted" | "completed" | "failed" | "stopped";

export interface ScanResumeCheckpoint {
  currentCursor: string | null;
  folderCursors: Record<string, string>;
  completedFolders: string[];
  seenSenderHashes: string[];
  seenMessageHashes: string[];
}

export interface ScanHistoryRecord {
  scanId: string;
  type: ScanType;
  status: ScanHistoryStatus;
  startedAt: number;
  updatedAt: number;
  completedAt: number | null;
  counters: ScanCounters;
  checkpoint: ScanResumeCheckpoint | null;
}

interface ScanStateDatabase {
  version: 1;
  accounts: Record<string, ScanHistoryRecord[]>;
}

interface EncryptedScanStateEnvelope {
  version: 1;
  algorithm: "aes-256-gcm";
  iv: string;
  authTag: string;
  ciphertext: string;
}

export interface ScanStateRepository {
  readonly persistent: boolean;
  list(accountKey: string): ScanHistoryRecord[];
  get(accountKey: string, scanId: string): ScanHistoryRecord | null;
  save(accountKey: string, record: ScanHistoryRecord): void;
  recoverInterrupted(): void;
}

export interface ScanStateRepositoryFactoryOptions {
  dataDirectory?: string;
  credentialVault?: CredentialVault;
  platform?: NodeJS.Platform;
}

export function emptyScanCounters(): ScanCounters {
  return {
    examined: 0,
    safe: 0,
    review: 0,
    highRisk: 0,
    confirmedThreat: 0,
    unknown: 0,
    skipped: 0,
    malformed: 0,
  };
}

function cloneCounters(value: ScanCounters): ScanCounters {
  return { ...value };
}

function cloneCheckpoint(value: ScanResumeCheckpoint | null): ScanResumeCheckpoint | null {
  return value ? {
    currentCursor: value.currentCursor,
    folderCursors: { ...value.folderCursors },
    completedFolders: [...value.completedFolders],
    seenSenderHashes: [...value.seenSenderHashes],
    seenMessageHashes: [...value.seenMessageHashes],
  } : null;
}

export function cloneScanHistoryRecord(value: ScanHistoryRecord): ScanHistoryRecord {
  return {
    ...value,
    counters: cloneCounters(value.counters),
    checkpoint: cloneCheckpoint(value.checkpoint),
  };
}

function validAccountKey(value: string): boolean {
  return /^[a-f0-9]{64}$/.test(value);
}

function validScanId(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function boundedInteger(value: unknown): number {
  return Number.isFinite(value) ? Math.max(0, Math.floor(Number(value))) : 0;
}

function sanitizeCounters(input: unknown): ScanCounters {
  const value = input && typeof input === "object" ? input as Record<string, unknown> : {};
  return {
    examined: boundedInteger(value.examined),
    safe: boundedInteger(value.safe),
    review: boundedInteger(value.review),
    highRisk: boundedInteger(value.highRisk),
    confirmedThreat: boundedInteger(value.confirmedThreat),
    unknown: boundedInteger(value.unknown),
    skipped: boundedInteger(value.skipped),
    malformed: boundedInteger(value.malformed),
  };
}

function sanitizeCursor(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string" || !value || Buffer.byteLength(value, "utf8") > MAX_CURSOR_BYTES) {
    throw new Error("Persisted scan cursor is invalid or exceeds the local checkpoint limit.");
  }
  return value;
}

function sanitizeHashList(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  const output: string[] = [];
  const seen = new Set<string>();
  for (const raw of input.slice(0, MAX_HASHES)) {
    if (typeof raw !== "string") continue;
    const value = raw.toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(value) || seen.has(value)) continue;
    seen.add(value);
    output.push(value);
  }
  return output;
}

function sanitizeCheckpoint(input: unknown): ScanResumeCheckpoint | null {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const value = input as Record<string, unknown>;
  const rawFolders = value.folderCursors && typeof value.folderCursors === "object" && !Array.isArray(value.folderCursors)
    ? value.folderCursors as Record<string, unknown>
    : {};
  const folderCursors: Record<string, string> = {};
  for (const [folder, rawCursor] of Object.entries(rawFolders).slice(0, MAX_COMPLETED_FOLDERS)) {
    if (!folder || folder.length > 512) continue;
    const cursor = sanitizeCursor(rawCursor);
    if (cursor) folderCursors[folder] = cursor;
  }
  const completedFolders = Array.isArray(value.completedFolders)
    ? [...new Set(value.completedFolders.filter((item): item is string => typeof item === "string" && item.length > 0 && item.length <= 512))]
        .slice(0, MAX_COMPLETED_FOLDERS)
    : [];
  return {
    currentCursor: sanitizeCursor(value.currentCursor),
    folderCursors,
    completedFolders,
    seenSenderHashes: sanitizeHashList(value.seenSenderHashes),
    seenMessageHashes: sanitizeHashList(value.seenMessageHashes),
  };
}

function sanitizeRecord(input: unknown): ScanHistoryRecord | null {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const value = input as Record<string, unknown>;
  if (typeof value.scanId !== "string" || !validScanId(value.scanId)) return null;
  if (value.type !== "quick" && value.type !== "full" && value.type !== "spam") return null;
  if (!["running", "interrupted", "completed", "failed", "stopped"].includes(String(value.status))) return null;
  const startedAt = boundedInteger(value.startedAt);
  const updatedAt = boundedInteger(value.updatedAt);
  const completedAt = value.completedAt === null ? null : boundedInteger(value.completedAt);
  if (!startedAt || !updatedAt) return null;
  return {
    scanId: value.scanId,
    type: value.type,
    status: value.status as ScanHistoryStatus,
    startedAt,
    updatedAt,
    completedAt,
    counters: sanitizeCounters(value.counters),
    checkpoint: sanitizeCheckpoint(value.checkpoint),
  };
}

function pruneHistory(records: ScanHistoryRecord[]): ScanHistoryRecord[] {
  return [...records]
    .sort((left, right) => right.updatedAt - left.updatedAt)
    .slice(0, MAX_HISTORY_PER_ACCOUNT)
    .map(cloneScanHistoryRecord);
}

export class InMemoryScanStateRepository implements ScanStateRepository {
  readonly persistent = false;
  private readonly accounts = new Map<string, ScanHistoryRecord[]>();

  list(accountKey: string): ScanHistoryRecord[] {
    if (!validAccountKey(accountKey)) throw new Error("Scan-history account key is invalid.");
    return (this.accounts.get(accountKey) ?? []).map(cloneScanHistoryRecord);
  }

  get(accountKey: string, scanId: string): ScanHistoryRecord | null {
    return this.list(accountKey).find((record) => record.scanId === scanId) ?? null;
  }

  save(accountKey: string, record: ScanHistoryRecord): void {
    if (!validAccountKey(accountKey)) throw new Error("Scan-history account key is invalid.");
    const normalized = sanitizeRecord(record);
    if (!normalized) throw new Error("Scan-history record is invalid.");
    const records = this.accounts.get(accountKey) ?? [];
    const next = records.filter((item) => item.scanId !== normalized.scanId);
    next.push(normalized);
    this.accounts.set(accountKey, pruneHistory(next));
  }

  recoverInterrupted(): void {
    const now = Date.now();
    for (const [accountKey, records] of this.accounts) {
      let changed = false;
      const next = records.map((record) => {
        if (record.status !== "running") return record;
        changed = true;
        return { ...record, status: "interrupted" as const, updatedAt: now };
      });
      if (changed) this.accounts.set(accountKey, pruneHistory(next));
    }
  }
}

export class EncryptedFileScanStateRepository implements ScanStateRepository {
  readonly persistent = true;
  private readonly databasePath: string;
  private readonly encryptionKey: Buffer;

  constructor(readonly dataDirectory: string, encryptionKey: Buffer) {
    if (!Buffer.isBuffer(encryptionKey) || encryptionKey.length !== KEY_BYTES) {
      throw new Error("Local scan-state encryption key is invalid.");
    }
    this.databasePath = join(dataDirectory, "scan-state.enc.json");
    this.encryptionKey = Buffer.from(encryptionKey);
  }

  list(accountKey: string): ScanHistoryRecord[] {
    if (!validAccountKey(accountKey)) throw new Error("Scan-history account key is invalid.");
    return (this.readDatabase().accounts[accountKey] ?? []).map(cloneScanHistoryRecord);
  }

  get(accountKey: string, scanId: string): ScanHistoryRecord | null {
    if (!validScanId(scanId)) return null;
    return this.list(accountKey).find((record) => record.scanId === scanId) ?? null;
  }

  save(accountKey: string, record: ScanHistoryRecord): void {
    if (!validAccountKey(accountKey)) throw new Error("Scan-history account key is invalid.");
    const normalized = sanitizeRecord(record);
    if (!normalized) throw new Error("Scan-history record is invalid.");
    const database = this.readDatabase();
    const records = database.accounts[accountKey] ?? [];
    const next = records.filter((item) => item.scanId !== normalized.scanId);
    next.push(normalized);
    database.accounts[accountKey] = pruneHistory(next);
    this.writeDatabase(database);
  }

  recoverInterrupted(): void {
    const database = this.readDatabase();
    const now = Date.now();
    let changed = false;
    for (const [accountKey, records] of Object.entries(database.accounts)) {
      database.accounts[accountKey] = records.map((record) => {
        if (record.status !== "running") return record;
        changed = true;
        return { ...record, status: "interrupted", updatedAt: now };
      });
    }
    if (changed) this.writeDatabase(database);
  }

  assertReadable(): void {
    void this.readDatabase();
  }

  private ensureDirectory(): void {
    mkdirSync(this.dataDirectory, { recursive: true, mode: 0o700 });
    try { chmodSync(this.dataDirectory, 0o700); } catch {}
  }

  private readDatabase(): ScanStateDatabase {
    if (!existsSync(this.databasePath)) return { version: DATABASE_VERSION, accounts: {} };
    try {
      const raw = readBoundedRegularFile(this.databasePath, {
        description: "Encrypted scan-state file",
        maxBytes: SCAN_STATE_ENCRYPTED_DATABASE_MAX_BYTES,
      });
      const envelope = JSON.parse(raw.toString("utf8")) as Partial<EncryptedScanStateEnvelope>;
      if (
        envelope.version !== DATABASE_VERSION ||
        envelope.algorithm !== ALGORITHM ||
        typeof envelope.iv !== "string" ||
        typeof envelope.authTag !== "string" ||
        typeof envelope.ciphertext !== "string"
      ) throw new Error("Unsupported encrypted scan-state format.");
      const decipher = createDecipheriv(ALGORITHM, this.encryptionKey, Buffer.from(envelope.iv, "base64"));
      decipher.setAAD(AAD);
      decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, "base64")),
        decipher.final(),
      ]).toString("utf8");
      if (Buffer.byteLength(plaintext, "utf8") > MAX_DATABASE_BYTES) {
        throw new Error("Scan-state database exceeds the local size limit.");
      }
      const parsed = JSON.parse(plaintext) as Partial<ScanStateDatabase>;
      if (parsed.version !== DATABASE_VERSION || !parsed.accounts || typeof parsed.accounts !== "object") {
        throw new Error("Unsupported scan-state database format.");
      }
      const accounts: Record<string, ScanHistoryRecord[]> = {};
      for (const [accountKey, rawRecords] of Object.entries(parsed.accounts)) {
        if (!validAccountKey(accountKey) || !Array.isArray(rawRecords)) continue;
        accounts[accountKey] = pruneHistory(rawRecords.map(sanitizeRecord).filter((record): record is ScanHistoryRecord => Boolean(record)));
      }
      return { version: DATABASE_VERSION, accounts };
    } catch (error) {
      throw new Error(`Encrypted local scan state could not be read: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private writeDatabase(database: ScanStateDatabase): void {
    this.ensureDirectory();
    const plaintext = JSON.stringify(database);
    if (Buffer.byteLength(plaintext, "utf8") > MAX_DATABASE_BYTES) {
      throw new Error("Scan-state database exceeds the local size limit.");
    }
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGORITHM, this.encryptionKey, iv);
    cipher.setAAD(AAD);
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const envelope: EncryptedScanStateEnvelope = {
      version: DATABASE_VERSION,
      algorithm: ALGORITHM,
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
    const serialized = JSON.stringify(envelope);
    if (Buffer.byteLength(serialized, "utf8") > SCAN_STATE_ENCRYPTED_DATABASE_MAX_BYTES) {
      throw new Error("Encrypted scan-state file exceeds the local size limit.");
    }
    const temporaryPath = `${this.databasePath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
    writeFileSync(temporaryPath, serialized, { mode: 0o600 });
    replaceFileFromTemporaryPath(temporaryPath, this.databasePath);
    try { chmodSync(this.databasePath, 0o600); } catch {}
  }
}

export async function createDefaultScanStateRepository(
  options: ScanStateRepositoryFactoryOptions = {},
): Promise<ScanStateRepository> {
  const dataDirectory = options.dataDirectory ?? defaultEmailShieldDataDirectory();
  const databasePath = join(dataDirectory, "scan-state.enc.json");
  const platform = options.platform ?? process.platform;
  const vault = options.credentialVault ?? createCredentialVault(platform);
  const databaseExists = existsSync(databasePath);

  if (!vault.capabilities().available) {
    if (databaseExists) {
      throw new Error("Encrypted scan history exists but its protected encryption key is unavailable on this platform.");
    }
    return new InMemoryScanStateRepository();
  }

  const resolved = await resolveDataBoundEncryptionKey({
    vault,
    legacyReference: KEY_REFERENCE,
    dataDirectory,
    platform,
    databaseExists,
    keyBytes: KEY_BYTES,
    label: "scan history",
    validateExistingKey: (candidate) => {
      new EncryptedFileScanStateRepository(dataDirectory, candidate).assertReadable();
    },
  });
  const repository = new EncryptedFileScanStateRepository(dataDirectory, resolved.key);
  repository.assertReadable();
  repository.recoverInterrupted();
  return repository;
}
