import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { CredentialReference, CredentialVault } from "../security/credentialVault.js";
import { createCredentialVault } from "../security/credentialVaultFactory.js";
import { resolveDataBoundEncryptionKey } from "../security/dataBoundEncryptionKey.js";
import { defaultEmailShieldDataDirectory } from "../security/dataDirectory.js";
import {
  encryptedJsonEnvelopeByteCeiling,
  readBoundedRegularFile,
  replaceFileFromTemporaryPath,
} from "../util/localFileIntegrity.js";
import {
  InMemoryInboundEventStateRepository,
  type InboundEventStateRepository,
  type InboundEventStateV1,
} from "./inboundEvents.js";

const DATABASE_VERSION = 1;
const ALGORITHM = "aes-256-gcm";
const KEY_BYTES = 32;
const AAD = Buffer.from("email-shield-inbound-event-state-v1", "utf8");
const MAX_STATE_BYTES = 1024 * 1024;
export const INBOUND_EVENT_ENCRYPTED_STATE_MAX_BYTES = encryptedJsonEnvelopeByteCeiling(MAX_STATE_BYTES);
const DATABASE_FILENAME = "inbound-event-state.enc.json";

const KEY_REFERENCE: CredentialReference = {
  id: "inbound-event-state-encryption-key-v1",
  kind: "local-encryption-key",
};

interface EncryptedInboundEventEnvelope {
  version: 1;
  algorithm: "aes-256-gcm";
  iv: string;
  authTag: string;
  ciphertext: string;
}

export interface InboundEventRepositoryFactoryOptions {
  dataDirectory?: string;
  credentialVault?: CredentialVault;
  platform?: NodeJS.Platform;
}

function normalizedState(input: unknown): InboundEventStateV1 {
  // Reuse the coordinator repository's strict schema validation rather than
  // maintaining a second parser for replay state.
  return new InMemoryInboundEventStateRepository(input as InboundEventStateV1).load();
}

function strictEnvelope(input: unknown): EncryptedInboundEventEnvelope {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Encrypted inbound event envelope must be an object.");
  const value = input as Record<string, unknown>;
  if (Object.keys(value).some((field) => !["version", "algorithm", "iv", "authTag", "ciphertext"].includes(field))) {
    throw new Error("Encrypted inbound event envelope contains unknown fields.");
  }
  if (value.version !== DATABASE_VERSION
    || value.algorithm !== ALGORITHM
    || typeof value.iv !== "string"
    || typeof value.authTag !== "string"
    || typeof value.ciphertext !== "string") {
    throw new Error("Unsupported encrypted inbound event state format.");
  }
  const iv = Buffer.from(value.iv, "base64");
  const tag = Buffer.from(value.authTag, "base64");
  if (iv.length !== 12 || tag.length !== 16) throw new Error("Encrypted inbound event envelope nonce or tag is invalid.");
  return value as unknown as EncryptedInboundEventEnvelope;
}

export class EncryptedFileInboundEventStateRepository implements InboundEventStateRepository {
  readonly persistent = true;
  readonly #databasePath: string;
  readonly #encryptionKey: Buffer;

  constructor(readonly dataDirectory: string, encryptionKey: Buffer) {
    if (!Buffer.isBuffer(encryptionKey) || encryptionKey.length !== KEY_BYTES) throw new Error("Inbound event state encryption key is invalid.");
    this.#databasePath = join(dataDirectory, DATABASE_FILENAME);
    this.#encryptionKey = Buffer.from(encryptionKey);
  }

  load(): InboundEventStateV1 {
    if (!existsSync(this.#databasePath)) return new InMemoryInboundEventStateRepository().load();
    try {
      const raw = readBoundedRegularFile(this.#databasePath, {
        description: "Encrypted inbound event state file",
        maxBytes: INBOUND_EVENT_ENCRYPTED_STATE_MAX_BYTES,
      });
      const envelope = strictEnvelope(JSON.parse(raw.toString("utf8")));
      const decipher = createDecipheriv(ALGORITHM, this.#encryptionKey, Buffer.from(envelope.iv, "base64"));
      decipher.setAAD(AAD);
      decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, "base64")),
        decipher.final(),
      ]);
      if (plaintext.length > MAX_STATE_BYTES) throw new Error("Inbound event replay state exceeds its size limit.");
      return normalizedState(JSON.parse(plaintext.toString("utf8")));
    } catch (error) {
      throw new Error(`Encrypted inbound event state could not be read: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  save(input: InboundEventStateV1): void {
    const state = normalizedState(input);
    const plaintext = Buffer.from(JSON.stringify(state), "utf8");
    if (plaintext.length > MAX_STATE_BYTES) throw new Error("Inbound event replay state exceeds its size limit.");
    mkdirSync(this.dataDirectory, { recursive: true, mode: 0o700 });
    try { chmodSync(this.dataDirectory, 0o700); } catch {}
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGORITHM, this.#encryptionKey, iv);
    cipher.setAAD(AAD);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const envelope: EncryptedInboundEventEnvelope = {
      version: DATABASE_VERSION,
      algorithm: ALGORITHM,
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
    const serialized = JSON.stringify(envelope);
    if (Buffer.byteLength(serialized, "utf8") > INBOUND_EVENT_ENCRYPTED_STATE_MAX_BYTES) {
      throw new Error("Encrypted inbound event state file exceeds its size limit.");
    }
    const temporaryPath = `${this.#databasePath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
    writeFileSync(temporaryPath, serialized, { mode: 0o600 });
    replaceFileFromTemporaryPath(temporaryPath, this.#databasePath);
    try { chmodSync(this.#databasePath, 0o600); } catch {}
  }

  assertReadable(): void {
    void this.load();
  }
}

export async function createDefaultInboundEventStateRepository(
  options: InboundEventRepositoryFactoryOptions = {},
): Promise<InboundEventStateRepository> {
  const dataDirectory = options.dataDirectory ?? defaultEmailShieldDataDirectory();
  const databasePath = join(dataDirectory, DATABASE_FILENAME);
  const platform = options.platform ?? process.platform;
  const vault = options.credentialVault ?? createCredentialVault(platform);
  const databaseExists = existsSync(databasePath);

  if (!vault.capabilities().available) {
    if (databaseExists) throw new Error("Encrypted inbound event state exists but its protected key is unavailable on this platform.");
    return new InMemoryInboundEventStateRepository();
  }

  const resolved = await resolveDataBoundEncryptionKey({
    vault,
    legacyReference: KEY_REFERENCE,
    dataDirectory,
    platform,
    databaseExists,
    keyBytes: KEY_BYTES,
    label: "inbound event",
    validateExistingKey: (candidate) => {
      new EncryptedFileInboundEventStateRepository(dataDirectory, candidate).assertReadable();
    },
  });
  const repository = new EncryptedFileInboundEventStateRepository(dataDirectory, resolved.key);
  repository.assertReadable();
  return repository;
}
