import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
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
import type { PersonalPolicySnapshot } from "../engine/layers/personalRules.js";
import type { AdapterConfig } from "./adapterConfig.js";

const DATABASE_VERSION = 1;
const ALGORITHM = "aes-256-gcm";
const AAD = Buffer.from("email-shield-personal-policy-v1", "utf8");
const MAX_RULES_PER_LIST = 10_000;

interface PolicyDatabase {
  version: 1;
  policies: Record<string, PersonalPolicySnapshot>;
}

interface EncryptedPolicyEnvelope {
  version: 1;
  algorithm: "aes-256-gcm";
  iv: string;
  authTag: string;
  ciphertext: string;
}

export interface PersonalPolicyRepository {
  load(accountKey: string): PersonalPolicySnapshot;
  save(accountKey: string, snapshot: PersonalPolicySnapshot): void;
}

function emptySnapshot(): PersonalPolicySnapshot {
  return {
    blockedSenders: [],
    blockedDomains: [],
    trustedSenders: [],
    approvedExceptions: [],
    unsubscribedActions: [],
    reportedCampaigns: [],
  };
}

function sanitizeList(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  const values: string[] = [];
  const seen = new Set<string>();

  for (const item of input.slice(0, MAX_RULES_PER_LIST)) {
    if (typeof item !== "string") continue;
    const value = item.trim().toLowerCase();
    if (!value || value.length > 512 || seen.has(value)) continue;
    seen.add(value);
    values.push(value);
  }
  return values;
}

export function sanitizePolicySnapshot(input: unknown): PersonalPolicySnapshot {
  const value = input && typeof input === "object"
    ? input as Partial<Record<keyof PersonalPolicySnapshot, unknown>>
    : {};
  return {
    blockedSenders: sanitizeList(value.blockedSenders),
    blockedDomains: sanitizeList(value.blockedDomains),
    trustedSenders: sanitizeList(value.trustedSenders),
    approvedExceptions: sanitizeList(value.approvedExceptions),
    unsubscribedActions: sanitizeList(value.unsubscribedActions),
    reportedCampaigns: sanitizeList(value.reportedCampaigns).filter((item) => /^[a-f0-9]{64}$/.test(item)),
  };
}

function cloneSnapshot(snapshot: PersonalPolicySnapshot): PersonalPolicySnapshot {
  return {
    blockedSenders: [...snapshot.blockedSenders],
    blockedDomains: [...snapshot.blockedDomains],
    trustedSenders: [...snapshot.trustedSenders],
    approvedExceptions: [...snapshot.approvedExceptions],
    unsubscribedActions: [...snapshot.unsubscribedActions],
    reportedCampaigns: [...snapshot.reportedCampaigns],
  };
}

export class InMemoryPolicyRepository implements PersonalPolicyRepository {
  private readonly policies = new Map<string, PersonalPolicySnapshot>();

  load(accountKey: string): PersonalPolicySnapshot {
    return cloneSnapshot(this.policies.get(accountKey) ?? emptySnapshot());
  }

  save(accountKey: string, snapshot: PersonalPolicySnapshot): void {
    this.policies.set(accountKey, sanitizePolicySnapshot(snapshot));
  }
}

export class EncryptedFilePolicyRepository implements PersonalPolicyRepository {
  readonly dataDirectory: string;
  private readonly keyPath: string;
  private readonly databasePath: string;
  private keyCache: Buffer | null = null;

  constructor(dataDirectory = process.env.EMAIL_SHIELD_DATA_DIR?.trim() || join(homedir(), ".email-shield")) {
    this.dataDirectory = dataDirectory;
    this.keyPath = join(dataDirectory, "personal-policy.key");
    this.databasePath = join(dataDirectory, "personal-policies.enc.json");
  }

  load(accountKey: string): PersonalPolicySnapshot {
    const database = this.readDatabase();
    return cloneSnapshot(database.policies[accountKey] ?? emptySnapshot());
  }

  save(accountKey: string, snapshot: PersonalPolicySnapshot): void {
    if (!/^[a-f0-9]{64}$/.test(accountKey)) throw new Error("Personal policy account key is invalid.");
    const database = this.readDatabase();
    database.policies[accountKey] = sanitizePolicySnapshot(snapshot);
    this.writeDatabase(database);
  }

  private ensureDirectory(): void {
    mkdirSync(this.dataDirectory, { recursive: true, mode: 0o700 });
    try { chmodSync(this.dataDirectory, 0o700); } catch {}
  }

  private readKey(): Buffer {
    if (this.keyCache) return this.keyCache;
    this.ensureDirectory();

    if (!existsSync(this.keyPath)) {
      const generated = randomBytes(32);
      try {
        writeFileSync(this.keyPath, generated, { mode: 0o600, flag: "wx" });
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code !== "EEXIST") throw error;
      }
    }

    const key = readFileSync(this.keyPath);
    if (key.length !== 32) throw new Error("Local personal policy encryption key is invalid.");
    try { chmodSync(this.keyPath, 0o600); } catch {}
    this.keyCache = key;
    return key;
  }

  private readDatabase(): PolicyDatabase {
    if (!existsSync(this.databasePath)) return { version: DATABASE_VERSION, policies: {} };

    try {
      const envelope = JSON.parse(readFileSync(this.databasePath, "utf8")) as Partial<EncryptedPolicyEnvelope>;
      if (
        envelope.version !== DATABASE_VERSION ||
        envelope.algorithm !== ALGORITHM ||
        typeof envelope.iv !== "string" ||
        typeof envelope.authTag !== "string" ||
        typeof envelope.ciphertext !== "string"
      ) throw new Error("Unsupported encrypted policy file format.");

      const decipher = createDecipheriv(ALGORITHM, this.readKey(), Buffer.from(envelope.iv, "base64"));
      decipher.setAAD(AAD);
      decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, "base64")),
        decipher.final(),
      ]).toString("utf8");

      const parsed = JSON.parse(plaintext) as Partial<PolicyDatabase>;
      if (parsed.version !== DATABASE_VERSION || !parsed.policies || typeof parsed.policies !== "object") {
        throw new Error("Unsupported personal policy database format.");
      }

      const policies: Record<string, PersonalPolicySnapshot> = {};
      for (const [accountKey, snapshot] of Object.entries(parsed.policies)) {
        if (/^[a-f0-9]{64}$/.test(accountKey)) policies[accountKey] = sanitizePolicySnapshot(snapshot);
      }
      return { version: DATABASE_VERSION, policies };
    } catch (error) {
      throw new Error(`Encrypted local personal policies could not be read: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private writeDatabase(database: PolicyDatabase): void {
    this.ensureDirectory();
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGORITHM, this.readKey(), iv);
    cipher.setAAD(AAD);
    const ciphertext = Buffer.concat([
      cipher.update(JSON.stringify(database), "utf8"),
      cipher.final(),
    ]);
    const envelope: EncryptedPolicyEnvelope = {
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

export function policyAccountKey(config: AdapterConfig): string {
  let identity: string;

  if (config.mode === "fixture") {
    identity = `fixture:${config.provider}`;
  } else {
    switch (config.provider) {
      case "icloud":
      case "yahoo":
        identity = `${config.provider}:${config.credentials.user.trim().toLowerCase()}`;
        break;
      case "imap":
        identity = `imap:${config.credentials.host.trim().toLowerCase()}:${config.credentials.port}:${config.credentials.user.trim().toLowerCase()}`;
        break;
      case "gmail":
        identity = config.credentials.accountSubject?.trim()
          ? `gmail-sub:${config.credentials.clientId.trim()}:${config.credentials.accountSubject.trim()}`
          : `gmail:${config.credentials.clientId}:${config.credentials.refreshToken}`;
        break;
      case "outlook":
        // Guided Microsoft OAuth uses Graph `/me.id`; refresh tokens rotate and
        // therefore must never define policy identity. Legacy developer sessions
        // retain their historical path so pre-guided test/dev state does not move.
        identity = config.credentials.accountId?.trim()
          ? `outlook-id:${config.credentials.clientId.trim()}:${config.credentials.accountId.trim()}`
          : `outlook:${config.credentials.tenantId ?? "common"}:${config.credentials.clientId}:${config.credentials.refreshToken}`;
        break;
    }
  }

  return createHash("sha256")
    .update("email-shield-policy-account-v1\0", "utf8")
    .update(identity, "utf8")
    .digest("hex");
}
