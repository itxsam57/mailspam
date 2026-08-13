import { createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { readBoundedUtf8File, replaceFileFromTemporaryPath } from "../util/localFileIntegrity.js";
import { SCAM_RISK_CATEGORIES, type ScamRiskCategory } from "./familyGuardian.js";

const VERSION = 1 as const;
const MAX_FILE_BYTES = 4 * 1024 * 1024;
const MAX_ACCOUNTS = 10_000;

export type FamilyGuardianCategoryPreference = "all" | "high_only" | "off";

export interface FamilyGuardianPreferences {
  notificationsPaused: boolean;
  /** Explicit opt-in. Never enabled by default. */
  highRiskMemberMode: boolean;
  categories: Record<ScamRiskCategory, FamilyGuardianCategoryPreference>;
  updatedAt: number;
}

interface Database {
  version: 1;
  accounts: Record<string, FamilyGuardianPreferences>;
}

function defaultCategories(): Record<ScamRiskCategory, FamilyGuardianCategoryPreference> {
  return Object.fromEntries(SCAM_RISK_CATEGORIES.map((category) => [category, "high_only"])) as Record<ScamRiskCategory, FamilyGuardianCategoryPreference>;
}

export function defaultFamilyGuardianPreferences(now = Date.now()): FamilyGuardianPreferences {
  return {
    notificationsPaused: false,
    highRiskMemberMode: false,
    categories: defaultCategories(),
    updatedAt: now,
  };
}

export function familyGuardianPreferenceKey(accountId: string): string {
  const normalized = accountId.trim();
  if (!normalized || normalized.length > 128 || /[\u0000-\u001f\u007f]/.test(normalized)) {
    throw new Error("Family Guardian account ID is invalid.");
  }
  return createHash("sha256")
    .update("email-shield-family-guardian-preferences-v1\0", "utf8")
    .update(normalized, "utf8")
    .digest("hex");
}

function normalizeCategoryPreference(value: unknown): FamilyGuardianCategoryPreference {
  if (value === "all" || value === "high_only" || value === "off") return value;
  throw new Error("Family Guardian category preference is invalid.");
}

export function normalizeFamilyGuardianPreferences(
  input: unknown,
  now = Date.now(),
): FamilyGuardianPreferences {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Family Guardian preferences are invalid.");
  const value = input as Record<string, unknown>;
  if (Object.keys(value).some((key) => !["notificationsPaused", "highRiskMemberMode", "categories", "updatedAt"].includes(key))) {
    throw new Error("Family Guardian preferences contain unsupported fields.");
  }
  if (typeof value.notificationsPaused !== "boolean" || typeof value.highRiskMemberMode !== "boolean") {
    throw new Error("Family Guardian preference flags are invalid.");
  }
  if (!value.categories || typeof value.categories !== "object" || Array.isArray(value.categories)) {
    throw new Error("Family Guardian category preferences are required.");
  }
  const categoriesInput = value.categories as Record<string, unknown>;
  if (Object.keys(categoriesInput).some((key) => !(SCAM_RISK_CATEGORIES as readonly string[]).includes(key))) {
    throw new Error("Family Guardian category preferences contain an unknown category.");
  }
  const categories = defaultCategories();
  for (const category of SCAM_RISK_CATEGORIES) {
    if (categoriesInput[category] !== undefined) categories[category] = normalizeCategoryPreference(categoriesInput[category]);
  }
  const updatedAt = value.updatedAt === undefined
    ? now
    : Number.isSafeInteger(value.updatedAt) && Number(value.updatedAt) > 0
      ? Number(value.updatedAt)
      : (() => { throw new Error("Family Guardian preference timestamp is invalid."); })();
  return {
    notificationsPaused: value.notificationsPaused,
    highRiskMemberMode: value.highRiskMemberMode,
    categories,
    updatedAt,
  };
}

export interface FamilyGuardianPreferencesRepository {
  load(accountId: string): FamilyGuardianPreferences;
  save(accountId: string, preferences: Omit<FamilyGuardianPreferences, "updatedAt"> | FamilyGuardianPreferences): FamilyGuardianPreferences;
}

/**
 * Preference-only persistence. The file stores SHA-256 account keys and generic
 * preference flags/categories only. It never stores account usernames, family
 * members, mailbox identities, threat examples, message content or provider
 * credentials. File permissions are owner-only where the platform supports it.
 */
export class FileFamilyGuardianPreferencesRepository implements FamilyGuardianPreferencesRepository {
  constructor(private readonly filePath: string) {}

  load(accountId: string): FamilyGuardianPreferences {
    const key = familyGuardianPreferenceKey(accountId);
    return structuredClone(this.read().accounts[key] ?? defaultFamilyGuardianPreferences());
  }

  save(accountId: string, input: Omit<FamilyGuardianPreferences, "updatedAt"> | FamilyGuardianPreferences): FamilyGuardianPreferences {
    const key = familyGuardianPreferenceKey(accountId);
    const database = this.read();
    const normalized = normalizeFamilyGuardianPreferences({ ...input, updatedAt: Date.now() });
    if (!database.accounts[key] && Object.keys(database.accounts).length >= MAX_ACCOUNTS) {
      throw new Error("Family Guardian preference store reached capacity.");
    }
    database.accounts[key] = normalized;
    this.write(database);
    return structuredClone(normalized);
  }

  private read(): Database {
    if (!existsSync(this.filePath)) return { version: VERSION, accounts: {} };
    const raw = readBoundedUtf8File(this.filePath, {
      description: "Family Guardian preferences",
      maxBytes: MAX_FILE_BYTES,
      requireOwnerOnly: true,
    });
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Family Guardian preference database is invalid.");
    const value = parsed as Record<string, unknown>;
    if (value.version !== VERSION || !value.accounts || typeof value.accounts !== "object" || Array.isArray(value.accounts)) {
      throw new Error("Family Guardian preference database format is unsupported.");
    }
    const entries = Object.entries(value.accounts as Record<string, unknown>);
    if (entries.length > MAX_ACCOUNTS) throw new Error("Family Guardian preference database exceeds capacity.");
    const accounts: Record<string, FamilyGuardianPreferences> = {};
    for (const [key, preferences] of entries) {
      if (!/^[a-f0-9]{64}$/.test(key)) throw new Error("Family Guardian preference account key is invalid.");
      accounts[key] = normalizeFamilyGuardianPreferences(preferences);
    }
    return { version: VERSION, accounts };
  }

  private write(database: Database): void {
    const serialized = JSON.stringify(database);
    if (Buffer.byteLength(serialized, "utf8") > MAX_FILE_BYTES) throw new Error("Family Guardian preference database exceeds its size limit.");
    const directory = dirname(this.filePath);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    try { chmodSync(directory, 0o700); } catch {}
    const temporaryPath = `${this.filePath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
    writeFileSync(temporaryPath, serialized, { mode: 0o600 });
    replaceFileFromTemporaryPath(temporaryPath, this.filePath);
    try { chmodSync(this.filePath, 0o600); } catch {}
  }
}
