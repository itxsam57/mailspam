import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  encryptedJsonEnvelopeByteCeiling,
  readBoundedRegularFile,
  replaceFileFromTemporaryPath,
} from "../util/localFileIntegrity.js";
import { normalizeAccountPlatformState } from "../platform/accountFamilyPersistence.js";
import { ACCOUNT_PLATFORM_SCHEMA_VERSION } from "../platform/accountFamilyTypes.js";
import {
  ACCOUNT_SERVICE_SCHEMA_VERSION,
  emptyAccountServiceState,
  type AccountServiceState,
} from "./types.js";

const MAX_ACCOUNT_SERVICE_STATE_BYTES = 4 * 1024 * 1024;
const ACCOUNT_SERVICE_ENCRYPTED_MAX_BYTES = encryptedJsonEnvelopeByteCeiling(MAX_ACCOUNT_SERVICE_STATE_BYTES);
const ALGORITHM = "aes-256-gcm";
const AAD = Buffer.from("email-shield-account-service-v1", "utf8");
const FILE_VERSION = 1;

interface EncryptedEnvelope {
  version: 1;
  algorithm: "aes-256-gcm";
  iv: string;
  authTag: string;
  ciphertext: string;
}

export interface AccountServiceStore {
  readonly persistent: boolean;
  load(): AccountServiceState;
  save(state: AccountServiceState): void;
}

function clone(state: AccountServiceState): AccountServiceState {
  return structuredClone(state);
}

export function normalizeAccountServiceState(input: unknown): AccountServiceState {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Account service state must be an object.");
  const value = input as Record<string, unknown>;
  if (Object.keys(value).some((field) => !["schemaVersion", "accounts", "familyCircles"].includes(field))) {
    throw new Error("Account service state contains unknown fields.");
  }
  if (value.schemaVersion !== ACCOUNT_SERVICE_SCHEMA_VERSION || !Array.isArray(value.accounts) || !Array.isArray(value.familyCircles)) {
    throw new Error("Unsupported account service state schema.");
  }
  // Reuse the canonical account/family persistence validator. The service has
  // no selected local account and never stores mailbox links.
  const normalized = normalizeAccountPlatformState({
    schemaVersion: ACCOUNT_PLATFORM_SCHEMA_VERSION,
    currentAccountId: null,
    accounts: value.accounts,
    familyCircles: value.familyCircles,
    mailboxLinks: [],
  });
  return {
    schemaVersion: ACCOUNT_SERVICE_SCHEMA_VERSION,
    accounts: normalized.accounts,
    familyCircles: normalized.familyCircles,
  };
}

export class InMemoryAccountServiceStore implements AccountServiceStore {
  readonly persistent = false;
  private state: AccountServiceState;

  constructor(initial: AccountServiceState = emptyAccountServiceState()) {
    this.state = normalizeAccountServiceState(initial);
  }

  load(): AccountServiceState { return clone(this.state); }
  save(state: AccountServiceState): void { this.state = normalizeAccountServiceState(state); }
}

export class EncryptedFileAccountServiceStore implements AccountServiceStore {
  readonly persistent = true;
  private readonly filePath: string;

  constructor(private readonly dataDirectory: string, private readonly key: Buffer) {
    if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error("Account service storage key must be exactly 32 bytes.");
    this.filePath = join(dataDirectory, "account-service.enc.json");
  }

  load(): AccountServiceState {
    if (!existsSync(this.filePath)) return emptyAccountServiceState();
    try {
      const raw = readBoundedRegularFile(this.filePath, {
        description: "Encrypted Email Shield account service state",
        maxBytes: ACCOUNT_SERVICE_ENCRYPTED_MAX_BYTES,
      });
      const envelope = JSON.parse(raw.toString("utf8")) as Partial<EncryptedEnvelope>;
      if (Object.keys(envelope).some((field) => !["version", "algorithm", "iv", "authTag", "ciphertext"].includes(field))) {
        throw new Error("Encrypted account service envelope contains unknown fields.");
      }
      if (envelope.version !== FILE_VERSION || envelope.algorithm !== ALGORITHM || typeof envelope.iv !== "string" || typeof envelope.authTag !== "string" || typeof envelope.ciphertext !== "string") {
        throw new Error("Encrypted account service envelope is invalid.");
      }
      const decipher = createDecipheriv(ALGORITHM, this.key, Buffer.from(envelope.iv, "base64"));
      decipher.setAAD(AAD);
      decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, "base64")),
        decipher.final(),
      ]).toString("utf8");
      if (Buffer.byteLength(plaintext, "utf8") > MAX_ACCOUNT_SERVICE_STATE_BYTES) throw new Error("Account service state exceeds its size limit.");
      return normalizeAccountServiceState(JSON.parse(plaintext));
    } catch (error) {
      throw new Error(`Encrypted account service state could not be read: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  save(state: AccountServiceState): void {
    const normalized = normalizeAccountServiceState(state);
    const plaintext = JSON.stringify(normalized);
    if (Buffer.byteLength(plaintext, "utf8") > MAX_ACCOUNT_SERVICE_STATE_BYTES) throw new Error("Account service state exceeds its size limit.");
    mkdirSync(this.dataDirectory, { recursive: true, mode: 0o700 });
    try { chmodSync(this.dataDirectory, 0o700); } catch {}
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGORITHM, this.key, iv);
    cipher.setAAD(AAD);
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const envelope: EncryptedEnvelope = {
      version: FILE_VERSION,
      algorithm: ALGORITHM,
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
    const serialized = JSON.stringify(envelope);
    if (Buffer.byteLength(serialized, "utf8") > ACCOUNT_SERVICE_ENCRYPTED_MAX_BYTES) throw new Error("Encrypted account service file exceeds its size limit.");
    const temporaryPath = `${this.filePath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
    writeFileSync(temporaryPath, serialized, { mode: 0o600 });
    replaceFileFromTemporaryPath(temporaryPath, this.filePath);
    try { chmodSync(this.filePath, 0o600); } catch {}
  }
}

export function accountServiceStoreFromEnvironment(options: {
  dataDirectory: string;
  storageKeyBase64?: string;
  production?: boolean;
}): AccountServiceStore {
  const encoded = options.storageKeyBase64?.trim();
  if (!encoded) {
    if (options.production) throw new Error("EMAIL_SHIELD_ACCOUNT_SERVICE_STORAGE_KEY is required for persistent production account service state.");
    return new InMemoryAccountServiceStore();
  }
  const key = Buffer.from(encoded, "base64");
  if (key.length !== 32) throw new Error("EMAIL_SHIELD_ACCOUNT_SERVICE_STORAGE_KEY must decode to exactly 32 bytes.");
  return new EncryptedFileAccountServiceStore(options.dataDirectory, key);
}
