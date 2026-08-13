import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import type { PersonalPolicySnapshot } from "../engine/layers/personalRules.js";
import type { CredentialReference, CredentialVault } from "../security/credentialVault.js";
import { createCredentialVault } from "../security/credentialVaultFactory.js";
import {
  dataBoundCredentialReference,
  resolveDataBoundEncryptionKey,
} from "../security/dataBoundEncryptionKey.js";
import { defaultEmailShieldDataDirectory } from "../security/dataDirectory.js";
import { encryptedJsonEnvelopeByteCeiling, readBoundedRegularFile, readBoundedUtf8File, replaceFileFromTemporaryPath } from "../util/localFileIntegrity.js";
import type { AdapterConfig } from "./adapterConfig.js";

const DATABASE_VERSION = 1;
const ALGORITHM = "aes-256-gcm";
const AAD = Buffer.from("email-shield-personal-policy-v1", "utf8");
const MAX_RULES_PER_LIST = 10_000;
const MAX_POLICY_PLAINTEXT_BYTES = 64 * 1024 * 1024;
export const POLICY_ENCRYPTED_DATABASE_MAX_BYTES = encryptedJsonEnvelopeByteCeiling(MAX_POLICY_PLAINTEXT_BYTES);
const POLICY_KEY_BYTES = 32;
const POLICY_KEY_REFERENCE: CredentialReference = {
  id: "personal-policy-encryption-key-v1",
  kind: "local-encryption-key",
};

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
  readonly persistent: boolean;
  load(accountKey: string): PersonalPolicySnapshot;
  save(accountKey: string, snapshot: PersonalPolicySnapshot): void;
}

export interface PersonalPolicyRepositoryFactoryOptions {
  dataDirectory?: string;
  credentialVault?: CredentialVault;
  platform?: NodeJS.Platform;
}

function emptySnapshot(): PersonalPolicySnapshot {
  return {
    blockedSenders: [],
    blockedDomains: [],
    catchTrashSenders: [],
    catchTrashDomains: [],
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
    catchTrashSenders: sanitizeList(value.catchTrashSenders),
    catchTrashDomains: sanitizeList(value.catchTrashDomains),
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
    catchTrashSenders: [...snapshot.catchTrashSenders],
    catchTrashDomains: [...snapshot.catchTrashDomains],
    trustedSenders: [...snapshot.trustedSenders],
    approvedExceptions: [...snapshot.approvedExceptions],
    unsubscribedActions: [...snapshot.unsubscribedActions],
    reportedCampaigns: [...snapshot.reportedCampaigns],
  };
}

export class InMemoryPolicyRepository implements PersonalPolicyRepository {
  readonly persistent = false;
  private readonly policies = new Map<string, PersonalPolicySnapshot>();

  load(accountKey: string): PersonalPolicySnapshot {
    return cloneSnapshot(this.policies.get(accountKey) ?? emptySnapshot());
  }

  save(accountKey: string, snapshot: PersonalPolicySnapshot): void {
    this.policies.set(accountKey, sanitizePolicySnapshot(snapshot));
  }
}

export class EncryptedFilePolicyRepository implements PersonalPolicyRepository {
  readonly persistent = true;
  readonly dataDirectory: string;
  private readonly databasePath: string;
  private readonly encryptionKey: Buffer;

  constructor(
    dataDirectory = defaultEmailShieldDataDirectory(),
    encryptionKey: Buffer,
  ) {
    if (!Buffer.isBuffer(encryptionKey) || encryptionKey.length !== POLICY_KEY_BYTES) {
      throw new Error("Local personal policy encryption key is invalid.");
    }
    this.dataDirectory = dataDirectory;
    this.databasePath = join(dataDirectory, "personal-policies.enc.json");
    this.encryptionKey = Buffer.from(encryptionKey);
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

  /** Validate the complete encrypted database before a legacy key is removed. */
  assertReadable(): void {
    void this.readDatabase();
  }

  private ensureDirectory(): void {
    mkdirSync(this.dataDirectory, { recursive: true, mode: 0o700 });
    try { chmodSync(this.dataDirectory, 0o700); } catch {}
  }

  private readDatabase(): PolicyDatabase {
    if (!existsSync(this.databasePath)) return { version: DATABASE_VERSION, policies: {} };

    try {
      const envelope = JSON.parse(readBoundedUtf8File(this.databasePath, {
        description: "Encrypted personal-policy database",
        maxBytes: POLICY_ENCRYPTED_DATABASE_MAX_BYTES,
      })) as Partial<EncryptedPolicyEnvelope>;
      if (
        envelope.version !== DATABASE_VERSION ||
        envelope.algorithm !== ALGORITHM ||
        typeof envelope.iv !== "string" ||
        typeof envelope.authTag !== "string" ||
        typeof envelope.ciphertext !== "string"
      ) throw new Error("Unsupported encrypted policy file format.");

      const decipher = createDecipheriv(ALGORITHM, this.encryptionKey, Buffer.from(envelope.iv, "base64"));
      decipher.setAAD(AAD);
      decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, "base64")),
        decipher.final(),
      ]).toString("utf8");

      if (Buffer.byteLength(plaintext, "utf8") > MAX_POLICY_PLAINTEXT_BYTES) {
        throw new Error("Personal-policy database exceeds the local size limit.");
      }
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
    const plaintext = JSON.stringify(database);
    if (Buffer.byteLength(plaintext, "utf8") > MAX_POLICY_PLAINTEXT_BYTES) {
      throw new Error("Personal-policy database exceeds the local size limit.");
    }
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGORITHM, this.encryptionKey, iv);
    cipher.setAAD(AAD);
    const ciphertext = Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final(),
    ]);
    const envelope: EncryptedPolicyEnvelope = {
      version: DATABASE_VERSION,
      algorithm: ALGORITHM,
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
    const serialized = JSON.stringify(envelope);
    if (Buffer.byteLength(serialized, "utf8") > POLICY_ENCRYPTED_DATABASE_MAX_BYTES) {
      throw new Error("Encrypted personal-policy database exceeds the local size limit.");
    }
    const temporaryPath = `${this.databasePath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
    writeFileSync(temporaryPath, serialized, { mode: 0o600 });
    replaceFileFromTemporaryPath(temporaryPath, this.databasePath);
    try { chmodSync(this.databasePath, 0o600); } catch {}
  }
}

function readLegacyPolicyKey(path: string): Buffer {
  try {
    return readBoundedRegularFile(path, {
      description: "Legacy personal-policy encryption key",
      maxBytes: POLICY_KEY_BYTES,
      exactBytes: POLICY_KEY_BYTES,
      requireOwnerOnly: true,
    });
  } catch {
    throw new Error("Legacy personal-policy encryption key is invalid; migration was not attempted.");
  }
}

function encodePolicyKey(key: Buffer): string {
  return key.toString("base64");
}

function decodePolicyKey(secret: string): Buffer {
  const normalized = secret.trim();
  const key = Buffer.from(normalized, "base64");
  if (key.length !== POLICY_KEY_BYTES || key.toString("base64") !== normalized) {
    throw new Error("Protected personal-policy encryption key is invalid.");
  }
  return key;
}

function sameKey(left: Buffer, right: Buffer): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

async function writeAndVerifyProtectedPolicyKey(
  vault: CredentialVault,
  reference: CredentialReference,
  key: Buffer,
): Promise<void> {
  await vault.write(reference, encodePolicyKey(key));
  const stored = await vault.read(reference);
  if (!stored) throw new Error("Protected personal-policy encryption key write was not readable.");
  const roundTrip = decodePolicyKey(stored);
  if (!sameKey(key, roundTrip)) {
    throw new Error("Protected personal-policy encryption key verification failed.");
  }
}

/**
 * Initialize local policy persistence once at desktop-process startup.
 *
 * Windows uses the existing OS credential-vault boundary. A legacy raw key file
 * is removed only after the encrypted database decrypts successfully with that
 * key and Credential Manager confirms an identical read-back. No new plaintext
 * key file is ever created.
 *
 * Platforms without a native vault keep an already-existing legacy key only for
 * backward compatibility. A fresh unsupported-platform install uses memory-only
 * personal policy state rather than creating another plaintext encryption key.
 */
export async function createDefaultPersonalPolicyRepository(
  options: PersonalPolicyRepositoryFactoryOptions = {},
): Promise<PersonalPolicyRepository> {
  const dataDirectory = options.dataDirectory ?? defaultEmailShieldDataDirectory();
  const keyPath = join(dataDirectory, "personal-policy.key");
  const databasePath = join(dataDirectory, "personal-policies.enc.json");
  const platform = options.platform ?? process.platform;
  const vault = options.credentialVault ?? createCredentialVault(platform);
  const legacyExists = existsSync(keyPath);
  const databaseExists = existsSync(databasePath);

  if (vault.capabilities().available) {
    const scopedReference = dataBoundCredentialReference(POLICY_KEY_REFERENCE, dataDirectory, platform);
    if (legacyExists) {
      const legacyKey = readLegacyPolicyKey(keyPath);
      const repository = new EncryptedFilePolicyRepository(dataDirectory, legacyKey);
      repository.assertReadable();
      const scopedSecret = await vault.read(scopedReference);
      if (scopedSecret) {
        let scopedKey: Buffer | null = null;
        try { scopedKey = decodePolicyKey(scopedSecret); } catch {}
        if (scopedKey && !sameKey(scopedKey, legacyKey)) {
          let scopedAuthenticates = false;
          try {
            new EncryptedFilePolicyRepository(dataDirectory, scopedKey).assertReadable();
            scopedAuthenticates = databaseExists;
          } catch {}
          if (scopedAuthenticates) {
            throw new Error("Data-bound and legacy personal-policy encryption keys disagree; the legacy key file was preserved.");
          }
        }
      }
      await writeAndVerifyProtectedPolicyKey(vault, scopedReference, legacyKey);
      try {
        rmSync(keyPath);
      } catch {
        throw new Error("Personal-policy key was protected, but the legacy plaintext key file could not be removed.");
      }
      return repository;
    }

    const resolved = await resolveDataBoundEncryptionKey({
      vault,
      legacyReference: POLICY_KEY_REFERENCE,
      dataDirectory,
      platform,
      databaseExists,
      keyBytes: POLICY_KEY_BYTES,
      label: "personal policy",
      validateExistingKey: (candidate) => {
        new EncryptedFilePolicyRepository(dataDirectory, candidate).assertReadable();
      },
    });
    return new EncryptedFilePolicyRepository(dataDirectory, resolved.key);
  }

  if (legacyExists) {
    const legacyKey = readLegacyPolicyKey(keyPath);
    const repository = new EncryptedFilePolicyRepository(dataDirectory, legacyKey);
    repository.assertReadable();
    return repository;
  }

  if (databaseExists) {
    throw new Error("Encrypted personal policies exist but no readable local encryption key is available on this platform.");
  }

  return new InMemoryPolicyRepository();
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
