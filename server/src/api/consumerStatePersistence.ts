import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  randomUUID,
} from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import type { CredentialReference, CredentialVault } from "../security/credentialVault.js";
import { createCredentialVault } from "../security/credentialVaultFactory.js";
import { defaultEmailShieldDataDirectory } from "../security/dataDirectory.js";
import { resolveDataBoundEncryptionKey } from "../security/dataBoundEncryptionKey.js";
import { encryptedJsonEnvelopeByteCeiling, readBoundedRegularFile, replaceFileFromTemporaryPath } from "../util/localFileIntegrity.js";
import {
  defaultProtectionSensitivityPreference,
  normalizeProtectionSensitivityProfile,
  type ProtectionSensitivityProfile,
} from "../consumer/protectionSensitivity.js";
import type { Provider } from "../canonical/envelope.js";

const VERSION = 1 as const;
const ALGORITHM = "aes-256-gcm";
const AAD = Buffer.from("email-shield-consumer-state-v1", "utf8");
const KEY_BYTES = 32;
const MAX_DATABASE_BYTES = 4 * 1024 * 1024;
const MAX_ACTIVITY_PER_ACCOUNT = 500;
const MAX_RULES_PER_ACCOUNT = 200;
const MAX_UNDO_IDS = 100;
const MAX_TEXT = 500;
const ENCRYPTED_MAX_BYTES = encryptedJsonEnvelopeByteCeiling(MAX_DATABASE_BYTES);
const KEY_REFERENCE: CredentialReference = { id: "consumer-state-encryption-key-v1", kind: "local-encryption-key" };

export type ConsumerRuleType = "trash_after_unsubscribe" | "mute_notifications" | "read_later" | "screen_first_contact";
export type ConsumerActivityKind =
  | "protected"
  | "flagged"
  | "quarantined"
  | "reported"
  | "blocked"
  | "unsubscribed"
  | "cleanup"
  | "restored"
  | "health_check"
  | "family"
  | "exposure"
  | "settings";
export type ConsumerActivitySeverity = "info" | "attention" | "warning" | "critical";

export interface ConsumerMailboxRule {
  ruleId: string;
  type: ConsumerRuleType;
  enabled: boolean;
  senderAddress: string | null;
  senderDomain: string | null;
  createdAt: number;
  expiresAt: number | null;
}

export interface ConsumerActivityRecord {
  activityId: string;
  kind: ConsumerActivityKind;
  severity: ConsumerActivitySeverity;
  provider: Provider | null;
  createdAt: number;
  title: string;
  detail: string;
  reasonCodes: string[];
  undo: null | {
    providerNativeIds: string[];
    expiresAt: number;
    usedAt: number | null;
  };
}

export interface PublicConsumerActivityRecord {
  activityId: string;
  kind: ConsumerActivityKind;
  severity: ConsumerActivitySeverity;
  provider: Provider | null;
  createdAt: number;
  title: string;
  detail: string;
  reasonCodes: string[];
  undoAvailable: boolean;
  undoExpiresAt: number | null;
  undone: boolean;
}

export interface ConsumerOnboardingState {
  completedSteps: string[];
  dismissedAt: number | null;
}

export interface ConsumerAccountState {
  sensitivity: ProtectionSensitivityProfile;
  rules: ConsumerMailboxRule[];
  activity: ConsumerActivityRecord[];
  richerLocalNotifications: boolean;
  onboarding: ConsumerOnboardingState;
}

interface ConsumerStateDatabase {
  version: 1;
  accounts: Record<string, ConsumerAccountState>;
}

interface EncryptedEnvelope {
  version: 1;
  algorithm: "aes-256-gcm";
  iv: string;
  authTag: string;
  ciphertext: string;
}

export interface ConsumerStateRepository {
  readonly persistent: boolean;
  snapshot(accountKey: string): ConsumerAccountState;
  setSensitivity(accountKey: string, profile: ProtectionSensitivityProfile): ConsumerAccountState;
  setRicherLocalNotifications(accountKey: string, enabled: boolean): ConsumerAccountState;
  setOnboarding(accountKey: string, input: ConsumerOnboardingState): ConsumerAccountState;
  upsertRule(accountKey: string, input: Omit<ConsumerMailboxRule, "ruleId" | "createdAt"> & { ruleId?: string }): ConsumerMailboxRule;
  removeRule(accountKey: string, ruleId: string): boolean;
  appendActivity(accountKey: string, input: Omit<ConsumerActivityRecord, "activityId" | "createdAt"> & { activityId?: string; createdAt?: number }): ConsumerActivityRecord;
  listActivity(accountKey: string): PublicConsumerActivityRecord[];
  getActivity(accountKey: string, activityId: string): ConsumerActivityRecord | null;
  markActivityUndone(accountKey: string, activityId: string, usedAt?: number): ConsumerActivityRecord;
  clearAccount(accountKey: string): void;
  clearActivity(accountKey: string): void;
}

export interface ConsumerStateFactoryOptions {
  dataDirectory?: string;
  credentialVault?: CredentialVault;
  platform?: NodeJS.Platform;
}

function accountKey(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(normalized)) throw new Error("Consumer-state account key is invalid.");
  return normalized;
}

function safeText(value: unknown, fallback = ""): string {
  if (typeof value !== "string") return fallback;
  return value.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim().slice(0, MAX_TEXT);
}

function safeTimestamp(value: unknown, nullable = false): number | null {
  if (nullable && (value === null || value === undefined)) return null;
  if (!Number.isSafeInteger(value) || Number(value) <= 0) return nullable ? null : Date.now();
  return Number(value);
}

function safeProvider(value: unknown): Provider | null {
  return value === "gmail" || value === "outlook" || value === "icloud" || value === "yahoo" || value === "imap" ? value : null;
}

function emptyAccount(): ConsumerAccountState {
  return {
    sensitivity: defaultProtectionSensitivityPreference().profile,
    rules: [],
    activity: [],
    richerLocalNotifications: false,
    onboarding: { completedSteps: [], dismissedAt: null },
  };
}

function normalizeRule(input: unknown): ConsumerMailboxRule | null {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const value = input as Record<string, unknown>;
  if (typeof value.ruleId !== "string" || !/^rule_[0-9a-f-]{36}$/i.test(value.ruleId)) return null;
  if (!(["trash_after_unsubscribe", "mute_notifications", "read_later", "screen_first_contact"] as const).includes(value.type as ConsumerRuleType)) return null;
  const senderAddress = typeof value.senderAddress === "string" ? value.senderAddress.trim().toLowerCase().slice(0, 320) : null;
  const senderDomain = typeof value.senderDomain === "string" ? value.senderDomain.trim().toLowerCase().replace(/^@/, "").slice(0, 253) : null;
  if (value.type !== "screen_first_contact" && !senderAddress && !senderDomain) return null;
  return {
    ruleId: value.ruleId,
    type: value.type as ConsumerRuleType,
    enabled: value.enabled === true,
    senderAddress,
    senderDomain,
    createdAt: safeTimestamp(value.createdAt)!,
    expiresAt: safeTimestamp(value.expiresAt, true),
  };
}

function safeReasonCodes(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  return [...new Set(input
    .filter((item): item is string => typeof item === "string")
    .map((item) => item.trim().toUpperCase())
    .filter((item) => /^[A-Z0-9_.:-]{1,100}$/.test(item)))]
    .slice(0, 20);
}

function normalizeActivity(input: unknown): ConsumerActivityRecord | null {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const value = input as Record<string, unknown>;
  const kinds: ConsumerActivityKind[] = ["protected", "flagged", "quarantined", "reported", "blocked", "unsubscribed", "cleanup", "restored", "health_check", "family", "exposure", "settings"];
  const severities: ConsumerActivitySeverity[] = ["info", "attention", "warning", "critical"];
  if (typeof value.activityId !== "string" || !/^act_[0-9a-f-]{36}$/i.test(value.activityId)) return null;
  if (!kinds.includes(value.kind as ConsumerActivityKind) || !severities.includes(value.severity as ConsumerActivitySeverity)) return null;
  let undo: ConsumerActivityRecord["undo"] = null;
  if (value.undo && typeof value.undo === "object" && !Array.isArray(value.undo)) {
    const rawUndo = value.undo as Record<string, unknown>;
    const ids = Array.isArray(rawUndo.providerNativeIds)
      ? rawUndo.providerNativeIds.filter((item): item is string => typeof item === "string" && item.length > 0 && item.length <= 4096).slice(0, MAX_UNDO_IDS)
      : [];
    const expiresAt = safeTimestamp(rawUndo.expiresAt, true);
    if (ids.length && expiresAt) undo = {
      providerNativeIds: [...new Set(ids)],
      expiresAt,
      usedAt: safeTimestamp(rawUndo.usedAt, true),
    };
  }
  return {
    activityId: value.activityId,
    kind: value.kind as ConsumerActivityKind,
    severity: value.severity as ConsumerActivitySeverity,
    provider: safeProvider(value.provider),
    createdAt: safeTimestamp(value.createdAt)!,
    title: safeText(value.title, "Protection activity"),
    detail: safeText(value.detail),
    reasonCodes: safeReasonCodes(value.reasonCodes),
    undo,
  };
}

function normalizeOnboarding(input: unknown): ConsumerOnboardingState {
  const value = input && typeof input === "object" && !Array.isArray(input) ? input as Record<string, unknown> : {};
  const completedSteps = Array.isArray(value.completedSteps)
    ? [...new Set(value.completedSteps.filter((item): item is string => typeof item === "string" && /^[a-z0-9_-]{1,50}$/i.test(item)))].slice(0, 30)
    : [];
  return { completedSteps, dismissedAt: safeTimestamp(value.dismissedAt, true) };
}

function normalizeAccountState(input: unknown): ConsumerAccountState {
  const value = input && typeof input === "object" && !Array.isArray(input) ? input as Record<string, unknown> : {};
  let sensitivity: ProtectionSensitivityProfile = "balanced";
  try { sensitivity = normalizeProtectionSensitivityProfile(value.sensitivity); } catch {}
  const rules = Array.isArray(value.rules) ? value.rules.map(normalizeRule).filter((rule): rule is ConsumerMailboxRule => Boolean(rule)).slice(0, MAX_RULES_PER_ACCOUNT) : [];
  const activity = Array.isArray(value.activity)
    ? value.activity.map(normalizeActivity).filter((entry): entry is ConsumerActivityRecord => Boolean(entry)).sort((a, b) => b.createdAt - a.createdAt).slice(0, MAX_ACTIVITY_PER_ACCOUNT)
    : [];
  return {
    sensitivity,
    rules,
    activity,
    richerLocalNotifications: value.richerLocalNotifications === true,
    onboarding: normalizeOnboarding(value.onboarding),
  };
}

function cloneAccount(value: ConsumerAccountState): ConsumerAccountState {
  return structuredClone(value);
}

function publicActivity(record: ConsumerActivityRecord, now = Date.now()): PublicConsumerActivityRecord {
  const undoAvailable = Boolean(record.undo && record.undo.usedAt === null && record.undo.expiresAt > now);
  return {
    activityId: record.activityId,
    kind: record.kind,
    severity: record.severity,
    provider: record.provider,
    createdAt: record.createdAt,
    title: record.title,
    detail: record.detail,
    reasonCodes: [...record.reasonCodes],
    undoAvailable,
    undoExpiresAt: record.undo?.expiresAt ?? null,
    undone: record.undo?.usedAt !== null && record.undo?.usedAt !== undefined,
  };
}

abstract class ConsumerStateBase implements ConsumerStateRepository {
  abstract readonly persistent: boolean;
  protected abstract loadDatabase(): ConsumerStateDatabase;
  protected abstract saveDatabase(database: ConsumerStateDatabase): void;

  snapshot(key: string): ConsumerAccountState {
    const id = accountKey(key);
    return cloneAccount(this.loadDatabase().accounts[id] ?? emptyAccount());
  }

  protected mutate(key: string, fn: (state: ConsumerAccountState) => void): ConsumerAccountState {
    const id = accountKey(key);
    const db = this.loadDatabase();
    const state = normalizeAccountState(db.accounts[id] ?? emptyAccount());
    fn(state);
    state.rules = state.rules.slice(0, MAX_RULES_PER_ACCOUNT);
    state.activity = state.activity.sort((a, b) => b.createdAt - a.createdAt).slice(0, MAX_ACTIVITY_PER_ACCOUNT);
    db.accounts[id] = state;
    this.saveDatabase(db);
    return cloneAccount(state);
  }

  setSensitivity(key: string, profile: ProtectionSensitivityProfile): ConsumerAccountState {
    const normalized = normalizeProtectionSensitivityProfile(profile);
    return this.mutate(key, (state) => { state.sensitivity = normalized; });
  }

  setRicherLocalNotifications(key: string, enabled: boolean): ConsumerAccountState {
    return this.mutate(key, (state) => { state.richerLocalNotifications = enabled === true; });
  }

  setOnboarding(key: string, input: ConsumerOnboardingState): ConsumerAccountState {
    const normalized = normalizeOnboarding(input);
    return this.mutate(key, (state) => { state.onboarding = normalized; });
  }

  upsertRule(key: string, input: Omit<ConsumerMailboxRule, "ruleId" | "createdAt"> & { ruleId?: string }): ConsumerMailboxRule {
    const raw = {
      ...input,
      ruleId: input.ruleId ?? `rule_${randomUUID()}`,
      createdAt: Date.now(),
    };
    const normalized = normalizeRule(raw);
    if (!normalized) throw new Error("Consumer mailbox rule is invalid.");
    this.mutate(key, (state) => {
      const index = state.rules.findIndex((rule) => rule.ruleId === normalized.ruleId);
      if (index >= 0) state.rules[index] = normalized;
      else state.rules.unshift(normalized);
    });
    return structuredClone(normalized);
  }

  removeRule(key: string, ruleId: string): boolean {
    if (!/^rule_[0-9a-f-]{36}$/i.test(ruleId)) return false;
    let removed = false;
    this.mutate(key, (state) => {
      const before = state.rules.length;
      state.rules = state.rules.filter((rule) => rule.ruleId !== ruleId);
      removed = state.rules.length !== before;
    });
    return removed;
  }

  appendActivity(key: string, input: Omit<ConsumerActivityRecord, "activityId" | "createdAt"> & { activityId?: string; createdAt?: number }): ConsumerActivityRecord {
    const normalized = normalizeActivity({
      ...input,
      activityId: input.activityId ?? `act_${randomUUID()}`,
      createdAt: input.createdAt ?? Date.now(),
    });
    if (!normalized) throw new Error("Consumer activity record is invalid.");
    this.mutate(key, (state) => {
      state.activity = state.activity.filter((entry) => entry.activityId !== normalized.activityId);
      state.activity.unshift(normalized);
    });
    return structuredClone(normalized);
  }

  listActivity(key: string): PublicConsumerActivityRecord[] {
    return this.snapshot(key).activity.map((entry) => publicActivity(entry));
  }

  getActivity(key: string, activityId: string): ConsumerActivityRecord | null {
    if (!/^act_[0-9a-f-]{36}$/i.test(activityId)) return null;
    return this.snapshot(key).activity.find((entry) => entry.activityId === activityId) ?? null;
  }

  markActivityUndone(key: string, activityId: string, usedAt = Date.now()): ConsumerActivityRecord {
    let found: ConsumerActivityRecord | null = null;
    this.mutate(key, (state) => {
      const entry = state.activity.find((item) => item.activityId === activityId);
      if (!entry || !entry.undo) throw new Error("This protection activity has no reversible provider action.");
      if (entry.undo.usedAt !== null) throw new Error("This protection activity was already undone.");
      if (entry.undo.expiresAt <= usedAt) throw new Error("The provider-safe Undo window has expired.");
      entry.undo.usedAt = usedAt;
      found = structuredClone(entry);
    });
    return found!;
  }

  clearAccount(key: string): void {
    const id = accountKey(key);
    const db = this.loadDatabase();
    delete db.accounts[id];
    this.saveDatabase(db);
  }

  clearActivity(key: string): void {
    this.mutate(key, (state) => { state.activity = []; });
  }
}

export class InMemoryConsumerStateRepository extends ConsumerStateBase {
  readonly persistent = false;
  private db: ConsumerStateDatabase = { version: VERSION, accounts: {} };
  protected loadDatabase(): ConsumerStateDatabase { return structuredClone(this.db); }
  protected saveDatabase(database: ConsumerStateDatabase): void { this.db = structuredClone(database); }
}

export class EncryptedFileConsumerStateRepository extends ConsumerStateBase {
  readonly persistent = true;
  private readonly databasePath: string;

  constructor(private readonly dataDirectory: string, private readonly key: Buffer) {
    super();
    if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES) throw new Error("Consumer-state encryption key is invalid.");
    this.databasePath = join(dataDirectory, "consumer-state.enc.json");
  }

  assertReadable(): void { void this.loadDatabase(); }

  protected loadDatabase(): ConsumerStateDatabase {
    if (!existsSync(this.databasePath)) return { version: VERSION, accounts: {} };
    try {
      const raw = readBoundedRegularFile(this.databasePath, { description: "Encrypted consumer-state file", maxBytes: ENCRYPTED_MAX_BYTES });
      const envelope = JSON.parse(raw.toString("utf8")) as Partial<EncryptedEnvelope>;
      if (envelope.version !== VERSION || envelope.algorithm !== ALGORITHM || typeof envelope.iv !== "string" || typeof envelope.authTag !== "string" || typeof envelope.ciphertext !== "string") {
        throw new Error("Unsupported encrypted consumer-state format.");
      }
      const decipher = createDecipheriv(ALGORITHM, this.key, Buffer.from(envelope.iv, "base64"));
      decipher.setAAD(AAD);
      decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));
      const plaintext = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64")), decipher.final()]).toString("utf8");
      if (Buffer.byteLength(plaintext, "utf8") > MAX_DATABASE_BYTES) throw new Error("Consumer-state database exceeds the local size limit.");
      const parsed = JSON.parse(plaintext) as Partial<ConsumerStateDatabase>;
      if (parsed.version !== VERSION || !parsed.accounts || typeof parsed.accounts !== "object" || Array.isArray(parsed.accounts)) throw new Error("Unsupported consumer-state database format.");
      const accounts: Record<string, ConsumerAccountState> = {};
      for (const [key, value] of Object.entries(parsed.accounts)) {
        if (!/^[a-f0-9]{64}$/.test(key)) continue;
        accounts[key] = normalizeAccountState(value);
      }
      return { version: VERSION, accounts };
    } catch (error) {
      throw new Error(`Encrypted local consumer state could not be read: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  protected saveDatabase(database: ConsumerStateDatabase): void {
    mkdirSync(this.dataDirectory, { recursive: true, mode: 0o700 });
    try { chmodSync(this.dataDirectory, 0o700); } catch {}
    const normalized: ConsumerStateDatabase = { version: VERSION, accounts: {} };
    for (const [key, value] of Object.entries(database.accounts)) {
      if (/^[a-f0-9]{64}$/.test(key)) normalized.accounts[key] = normalizeAccountState(value);
    }
    const plaintext = JSON.stringify(normalized);
    if (Buffer.byteLength(plaintext, "utf8") > MAX_DATABASE_BYTES) throw new Error("Consumer-state database exceeds the local size limit.");
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGORITHM, this.key, iv);
    cipher.setAAD(AAD);
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const envelope: EncryptedEnvelope = {
      version: VERSION,
      algorithm: ALGORITHM,
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
    const serialized = JSON.stringify(envelope);
    if (Buffer.byteLength(serialized, "utf8") > ENCRYPTED_MAX_BYTES) throw new Error("Encrypted consumer-state file exceeds the local size limit.");
    const temp = `${this.databasePath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
    writeFileSync(temp, serialized, { mode: 0o600 });
    replaceFileFromTemporaryPath(temp, this.databasePath);
    try { chmodSync(this.databasePath, 0o600); } catch {}
  }
}

export async function createDefaultConsumerStateRepository(options: ConsumerStateFactoryOptions = {}): Promise<ConsumerStateRepository> {
  const dataDirectory = options.dataDirectory ?? defaultEmailShieldDataDirectory();
  const databasePath = join(dataDirectory, "consumer-state.enc.json");
  const platform = options.platform ?? process.platform;
  const vault = options.credentialVault ?? createCredentialVault(platform);
  const databaseExists = existsSync(databasePath);
  if (!vault.capabilities().available) {
    if (databaseExists) throw new Error("Encrypted consumer state exists but its protected encryption key is unavailable on this platform.");
    return new InMemoryConsumerStateRepository();
  }
  const resolved = await resolveDataBoundEncryptionKey({
    vault,
    legacyReference: KEY_REFERENCE,
    dataDirectory,
    platform,
    databaseExists,
    keyBytes: KEY_BYTES,
    label: "consumer state",
    validateExistingKey: (candidate) => new EncryptedFileConsumerStateRepository(dataDirectory, candidate).assertReadable(),
  });
  const repository = new EncryptedFileConsumerStateRepository(dataDirectory, resolved.key);
  repository.assertReadable();
  return repository;
}
