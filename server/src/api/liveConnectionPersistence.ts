import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Provider } from "../canonical/envelope.js";
import {
  type CredentialReference,
  type CredentialVault,
  validateCredentialReference,
} from "../security/credentialVault.js";
import { createCredentialVault } from "../security/credentialVaultFactory.js";
import { resolveDataBoundEncryptionKey } from "../security/dataBoundEncryptionKey.js";
import { defaultEmailShieldDataDirectory } from "../security/dataDirectory.js";
import type { SecureAdapterConfig, SecretHandle } from "../security/secureAdapterConfig.js";
import {
  encryptedJsonEnvelopeByteCeiling,
  readBoundedRegularFile,
  replaceFileFromTemporaryPath,
} from "../util/localFileIntegrity.js";
import type { AccountSession } from "./sessionStore.js";
import { policyAccountKey } from "./policyPersistence.js";

const DATABASE_VERSION = 1;
const ALGORITHM = "aes-256-gcm";
const KEY_BYTES = 32;
const AAD = Buffer.from("email-shield-live-connections-v1", "utf8");
const DATABASE_FILENAME = "live-connections.enc.json";
const MAX_CONNECTIONS = 64;
const MAX_LABEL_CHARS = 512;
const MAX_IDENTITY_CHARS = 2048;
const MAX_HOST_CHARS = 253;
const MAX_PLAINTEXT_BYTES = 1024 * 1024;
export const LIVE_CONNECTIONS_ENCRYPTED_MAX_BYTES = encryptedJsonEnvelopeByteCeiling(MAX_PLAINTEXT_BYTES);

const KEY_REFERENCE: CredentialReference = {
  id: "live-connections-encryption-key-v1",
  kind: "local-encryption-key",
};

interface EncryptedEnvelope {
  version: 1;
  algorithm: "aes-256-gcm";
  iv: string;
  authTag: string;
  ciphertext: string;
}

type PersistentSecretReference = {
  storage: "vault";
  reference: CredentialReference;
};

export type PersistentLiveConnection =
  | {
      provider: "gmail";
      label: string;
      policyAccountKey: string;
      credentials: {
        clientId: string;
        accountSubject: string;
        refreshToken: PersistentSecretReference;
        clientSecret?: PersistentSecretReference;
      };
    }
  | {
      provider: "outlook";
      label: string;
      policyAccountKey: string;
      credentials: {
        clientId: string;
        accountId: string;
        refreshToken: PersistentSecretReference;
        tenantId?: string;
      };
    }
  | {
      provider: "icloud" | "yahoo";
      label: string;
      policyAccountKey: string;
      credentials: {
        user: string;
        appPassword: PersistentSecretReference;
      };
    }
  | {
      provider: "imap";
      label: string;
      policyAccountKey: string;
      credentials: {
        host: string;
        port: number;
        secure: boolean;
        user: string;
        appPassword: PersistentSecretReference;
      };
    };

interface LiveConnectionDatabase {
  version: 1;
  connections: PersistentLiveConnection[];
}

export interface LiveConnectionPersistence {
  readonly persistent: boolean;
  list(): PersistentLiveConnection[];
  remember(session: AccountSession): void;
  remove(policyAccountKey: string): void;
}

export interface LiveConnectionPersistenceFactoryOptions {
  dataDirectory?: string;
  credentialVault?: CredentialVault;
  platform?: NodeJS.Platform;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object.`);
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  if (Object.keys(value).some((key) => !allowed.includes(key))) throw new Error(`${label} contains unknown fields.`);
}

function boundedString(value: unknown, label: string, maxChars = MAX_IDENTITY_CHARS): string {
  if (typeof value !== "string") throw new Error(`${label} must be a string.`);
  const normalized = value.trim();
  if (!normalized || normalized.length > maxChars || /[\r\n\0]/.test(normalized)) throw new Error(`${label} is invalid.`);
  return normalized;
}

function policyKey(value: unknown): string {
  const normalized = boundedString(value, "Live connection policy account key", 64).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) throw new Error("Live connection policy account key is invalid.");
  return normalized;
}

function vaultHandle(value: unknown, expectedKind: CredentialReference["kind"], label: string): PersistentSecretReference {
  const handle = record(value, label);
  exactKeys(handle, ["storage", "reference"], label);
  if (handle.storage !== "vault") throw new Error(`${label} must use the native credential vault.`);
  const referenceRecord = record(handle.reference, `${label} reference`);
  exactKeys(referenceRecord, ["id", "kind"], `${label} reference`);
  const reference: CredentialReference = {
    id: boundedString(referenceRecord.id, `${label} reference id`, 160),
    kind: referenceRecord.kind as CredentialReference["kind"],
  };
  validateCredentialReference(reference);
  if (reference.kind !== expectedKind) throw new Error(`${label} reference kind is invalid.`);
  return { storage: "vault", reference: { ...reference } };
}

function validateConnection(input: unknown): PersistentLiveConnection {
  const value = record(input, "Live connection");
  exactKeys(value, ["provider", "label", "policyAccountKey", "credentials"], "Live connection");
  const provider = value.provider;
  if (!["gmail", "outlook", "icloud", "yahoo", "imap"].includes(String(provider))) throw new Error("Live connection provider is unsupported.");
  const label = boundedString(value.label, "Live connection label", MAX_LABEL_CHARS);
  const expectedPolicyKey = policyKey(value.policyAccountKey);
  const credentials = record(value.credentials, "Live connection credentials");

  let connection: PersistentLiveConnection;
  if (provider === "gmail") {
    exactKeys(credentials, ["clientId", "accountSubject", "refreshToken", "clientSecret"], "Gmail connection credentials");
    const clientId = boundedString(credentials.clientId, "Gmail client ID");
    const accountSubject = boundedString(credentials.accountSubject, "Gmail account subject");
    connection = {
      provider,
      label,
      policyAccountKey: expectedPolicyKey,
      credentials: {
        clientId,
        accountSubject,
        refreshToken: vaultHandle(credentials.refreshToken, "oauth-refresh-token", "Gmail refresh token"),
        ...(credentials.clientSecret === undefined ? {} : {
          clientSecret: vaultHandle(credentials.clientSecret, "oauth-client-secret", "Gmail OAuth client secret"),
        }),
      },
    };
  } else if (provider === "outlook") {
    exactKeys(credentials, ["clientId", "accountId", "refreshToken", "tenantId"], "Outlook connection credentials");
    const tenantId = credentials.tenantId === undefined ? undefined : boundedString(credentials.tenantId, "Outlook tenant ID");
    connection = {
      provider,
      label,
      policyAccountKey: expectedPolicyKey,
      credentials: {
        clientId: boundedString(credentials.clientId, "Outlook client ID"),
        accountId: boundedString(credentials.accountId, "Outlook account ID"),
        refreshToken: vaultHandle(credentials.refreshToken, "oauth-refresh-token", "Outlook refresh token"),
        ...(tenantId ? { tenantId } : {}),
      },
    };
  } else if (provider === "icloud" || provider === "yahoo") {
    exactKeys(credentials, ["user", "appPassword"], `${provider} connection credentials`);
    connection = {
      provider,
      label,
      policyAccountKey: expectedPolicyKey,
      credentials: {
        user: boundedString(credentials.user, `${provider} user`),
        appPassword: vaultHandle(credentials.appPassword, "imap-app-password", `${provider} app password`),
      },
    };
  } else {
    exactKeys(credentials, ["host", "port", "secure", "user", "appPassword"], "IMAP connection credentials");
    const port = Number(credentials.port);
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("IMAP port is invalid.");
    if (typeof credentials.secure !== "boolean") throw new Error("IMAP secure transport flag is invalid.");
    connection = {
      provider: "imap",
      label,
      policyAccountKey: expectedPolicyKey,
      credentials: {
        host: boundedString(credentials.host, "IMAP host", MAX_HOST_CHARS).toLowerCase(),
        port,
        secure: credentials.secure,
        user: boundedString(credentials.user, "IMAP user"),
        appPassword: vaultHandle(credentials.appPassword, "imap-app-password", "IMAP app password"),
      },
    };
  }

  const derived = policyAccountKeyFromPersistentConnection(connection);
  if (derived !== expectedPolicyKey) throw new Error("Live connection identity does not match its policy account key.");
  return connection;
}

function normalizeDatabase(input: unknown): LiveConnectionDatabase {
  const value = record(input, "Live connection database");
  exactKeys(value, ["version", "connections"], "Live connection database");
  if (value.version !== DATABASE_VERSION || !Array.isArray(value.connections) || value.connections.length > MAX_CONNECTIONS) {
    throw new Error("Live connection database format is invalid.");
  }
  const connections = value.connections.map(validateConnection);
  const seen = new Set<string>();
  for (const connection of connections) {
    if (seen.has(connection.policyAccountKey)) throw new Error("Live connection database contains a duplicate mailbox identity.");
    seen.add(connection.policyAccountKey);
  }
  return { version: DATABASE_VERSION, connections };
}

function strictEnvelope(input: unknown): EncryptedEnvelope {
  const value = record(input, "Encrypted live connection envelope");
  exactKeys(value, ["version", "algorithm", "iv", "authTag", "ciphertext"], "Encrypted live connection envelope");
  if (value.version !== DATABASE_VERSION || value.algorithm !== ALGORITHM
    || typeof value.iv !== "string" || typeof value.authTag !== "string" || typeof value.ciphertext !== "string") {
    throw new Error("Encrypted live connection envelope format is invalid.");
  }
  if (Buffer.from(value.iv, "base64").length !== 12 || Buffer.from(value.authTag, "base64").length !== 16) {
    throw new Error("Encrypted live connection envelope nonce or tag is invalid.");
  }
  return value as unknown as EncryptedEnvelope;
}

function requireVaultSecret(handle: SecretHandle | undefined, label: string, expectedKind: CredentialReference["kind"]): PersistentSecretReference | undefined {
  if (handle === undefined) return undefined;
  if (handle.storage !== "vault") throw new Error(`${label} is not persistable because it is not protected by the native credential vault.`);
  validateCredentialReference(handle.reference);
  if (handle.reference.kind !== expectedKind) throw new Error(`${label} reference kind is invalid.`);
  return { storage: "vault", reference: { ...handle.reference } };
}

export function persistentConnectionFromSession(session: AccountSession): PersistentLiveConnection {
  if (session.config.mode !== "live") throw new Error("Only live mailbox connections may enter the live connection registry.");
  const common = {
    label: boundedString(session.label, "Live connection label", MAX_LABEL_CHARS),
    policyAccountKey: policyKey(session.policyAccountKey),
  };
  let connection: PersistentLiveConnection;
  switch (session.config.provider) {
    case "gmail": {
      const accountSubject = boundedString(session.config.credentials.accountSubject, "Gmail account subject");
      connection = {
        provider: "gmail",
        ...common,
        credentials: {
          clientId: boundedString(session.config.credentials.clientId, "Gmail client ID"),
          accountSubject,
          refreshToken: requireVaultSecret(session.config.credentials.refreshToken, "Gmail refresh token", "oauth-refresh-token")!,
          ...(session.config.credentials.clientSecret
            ? { clientSecret: requireVaultSecret(session.config.credentials.clientSecret, "Gmail OAuth client secret", "oauth-client-secret")! }
            : {}),
        },
      };
      break;
    }
    case "outlook": {
      const accountId = boundedString(session.config.credentials.accountId, "Outlook account ID");
      if (session.config.credentials.clientSecret) throw new Error("Confidential-client Outlook credentials are not consumer-persistable; use the public-client guided OAuth flow.");
      connection = {
        provider: "outlook",
        ...common,
        credentials: {
          clientId: boundedString(session.config.credentials.clientId, "Outlook client ID"),
          accountId,
          refreshToken: requireVaultSecret(session.config.credentials.refreshToken, "Outlook refresh token", "oauth-refresh-token")!,
          ...(session.config.credentials.tenantId ? { tenantId: boundedString(session.config.credentials.tenantId, "Outlook tenant ID") } : {}),
        },
      };
      break;
    }
    case "icloud":
    case "yahoo":
      connection = {
        provider: session.config.provider,
        ...common,
        credentials: {
          user: boundedString(session.config.credentials.user, `${session.config.provider} user`),
          appPassword: requireVaultSecret(session.config.credentials.appPassword, `${session.config.provider} app password`, "imap-app-password")!,
        },
      };
      break;
    case "imap":
      connection = {
        provider: "imap",
        ...common,
        credentials: {
          host: boundedString(session.config.credentials.host, "IMAP host", MAX_HOST_CHARS).toLowerCase(),
          port: session.config.credentials.port,
          secure: session.config.credentials.secure,
          user: boundedString(session.config.credentials.user, "IMAP user"),
          appPassword: requireVaultSecret(session.config.credentials.appPassword, "IMAP app password", "imap-app-password")!,
        },
      };
      break;
  }
  return validateConnection(connection);
}

export function secureConfigFromPersistentConnection(connection: PersistentLiveConnection): SecureAdapterConfig {
  const valid = validateConnection(connection);
  switch (valid.provider) {
    case "gmail":
      return {
        provider: "gmail",
        mode: "live",
        credentials: {
          clientId: valid.credentials.clientId,
          accountSubject: valid.credentials.accountSubject,
          refreshToken: structuredClone(valid.credentials.refreshToken),
          ...(valid.credentials.clientSecret ? { clientSecret: structuredClone(valid.credentials.clientSecret) } : {}),
        },
      };
    case "outlook":
      return {
        provider: "outlook",
        mode: "live",
        credentials: {
          clientId: valid.credentials.clientId,
          accountId: valid.credentials.accountId,
          refreshToken: structuredClone(valid.credentials.refreshToken),
          ...(valid.credentials.tenantId ? { tenantId: valid.credentials.tenantId } : {}),
        },
      };
    case "icloud":
    case "yahoo":
      return {
        provider: valid.provider,
        mode: "live",
        credentials: {
          user: valid.credentials.user,
          appPassword: structuredClone(valid.credentials.appPassword),
        },
      };
    case "imap":
      return {
        provider: "imap",
        mode: "live",
        credentials: {
          host: valid.credentials.host,
          port: valid.credentials.port,
          secure: valid.credentials.secure,
          user: valid.credentials.user,
          appPassword: structuredClone(valid.credentials.appPassword),
        },
      };
  }
}

export function policyAccountKeyFromPersistentConnection(connection: PersistentLiveConnection): string {
  const value = connection;
  switch (value.provider) {
    case "gmail":
      return policyAccountKey({
        provider: "gmail",
        mode: "live",
        credentials: {
          clientId: value.credentials.clientId,
          refreshToken: "persistent-vault-handle",
          accountSubject: value.credentials.accountSubject,
        },
      });
    case "outlook":
      return policyAccountKey({
        provider: "outlook",
        mode: "live",
        credentials: {
          clientId: value.credentials.clientId,
          refreshToken: "persistent-vault-handle",
          accountId: value.credentials.accountId,
          tenantId: value.credentials.tenantId,
        },
      });
    case "icloud":
    case "yahoo":
      return policyAccountKey({
        provider: value.provider,
        mode: "live",
        credentials: { user: value.credentials.user, appPassword: "persistent-vault-handle" },
      });
    case "imap":
      return policyAccountKey({
        provider: "imap",
        mode: "live",
        credentials: {
          host: value.credentials.host,
          port: value.credentials.port,
          secure: value.credentials.secure,
          user: value.credentials.user,
          appPassword: "persistent-vault-handle",
        },
      });
  }
}

export class InMemoryLiveConnectionPersistence implements LiveConnectionPersistence {
  readonly persistent = false;
  #connections: PersistentLiveConnection[] = [];

  list(): PersistentLiveConnection[] {
    return structuredClone(this.#connections);
  }

  remember(session: AccountSession): void {
    if (session.config.mode !== "live") return;
    const connection = persistentConnectionFromSession(session);
    this.#connections = [...this.#connections.filter((item) => item.policyAccountKey !== connection.policyAccountKey), connection];
  }

  remove(accountKey: string): void {
    this.#connections = this.#connections.filter((item) => item.policyAccountKey !== accountKey);
  }
}

export const noLiveConnectionPersistence: LiveConnectionPersistence = {
  persistent: false,
  list: () => [],
  remember: () => undefined,
  remove: () => undefined,
};

export class EncryptedFileLiveConnectionPersistence implements LiveConnectionPersistence {
  readonly persistent = true;
  readonly #databasePath: string;
  readonly #encryptionKey: Buffer;

  constructor(readonly dataDirectory: string, encryptionKey: Buffer) {
    if (!Buffer.isBuffer(encryptionKey) || encryptionKey.length !== KEY_BYTES) throw new Error("Live connection encryption key is invalid.");
    this.#databasePath = join(dataDirectory, DATABASE_FILENAME);
    this.#encryptionKey = Buffer.from(encryptionKey);
  }

  list(): PersistentLiveConnection[] {
    return this.#read().connections;
  }

  remember(session: AccountSession): void {
    if (session.config.mode !== "live") return;
    const connection = persistentConnectionFromSession(session);
    const database = this.#read();
    const remaining = database.connections.filter((item) => item.policyAccountKey !== connection.policyAccountKey);
    if (remaining.length >= MAX_CONNECTIONS) throw new Error(`Email Shield supports at most ${MAX_CONNECTIONS} persistent live mailbox connections.`);
    database.connections = [...remaining, connection];
    this.#write(database);
  }

  remove(accountKey: string): void {
    const normalized = policyKey(accountKey);
    const database = this.#read();
    const next = database.connections.filter((item) => item.policyAccountKey !== normalized);
    if (next.length === database.connections.length) return;
    database.connections = next;
    this.#write(database);
  }

  assertReadable(): void {
    void this.#read();
  }

  #read(): LiveConnectionDatabase {
    if (!existsSync(this.#databasePath)) return { version: DATABASE_VERSION, connections: [] };
    try {
      const raw = readBoundedRegularFile(this.#databasePath, {
        description: "Encrypted live connection registry",
        maxBytes: LIVE_CONNECTIONS_ENCRYPTED_MAX_BYTES,
      });
      const envelope = strictEnvelope(JSON.parse(raw.toString("utf8")));
      const decipher = createDecipheriv(ALGORITHM, this.#encryptionKey, Buffer.from(envelope.iv, "base64"));
      decipher.setAAD(AAD);
      decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, "base64")),
        decipher.final(),
      ]);
      if (plaintext.length > MAX_PLAINTEXT_BYTES) throw new Error("Live connection registry exceeds its resource limit.");
      return normalizeDatabase(JSON.parse(plaintext.toString("utf8")));
    } catch (error) {
      throw new Error(`Encrypted live connections could not be read: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  #write(database: LiveConnectionDatabase): void {
    const normalized = normalizeDatabase(database);
    const plaintext = Buffer.from(JSON.stringify(normalized), "utf8");
    if (plaintext.length > MAX_PLAINTEXT_BYTES) throw new Error("Live connection registry exceeds its resource limit.");
    mkdirSync(this.dataDirectory, { recursive: true, mode: 0o700 });
    try { chmodSync(this.dataDirectory, 0o700); } catch {}
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGORITHM, this.#encryptionKey, iv);
    cipher.setAAD(AAD);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const envelope: EncryptedEnvelope = {
      version: DATABASE_VERSION,
      algorithm: ALGORITHM,
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
    const serialized = JSON.stringify(envelope);
    if (Buffer.byteLength(serialized, "utf8") > LIVE_CONNECTIONS_ENCRYPTED_MAX_BYTES) throw new Error("Encrypted live connection registry exceeds its resource limit.");
    const temporaryPath = `${this.#databasePath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
    writeFileSync(temporaryPath, serialized, { mode: 0o600 });
    replaceFileFromTemporaryPath(temporaryPath, this.#databasePath);
    try { chmodSync(this.#databasePath, 0o600); } catch {}
  }
}

export async function createDefaultLiveConnectionPersistence(
  options: LiveConnectionPersistenceFactoryOptions = {},
): Promise<LiveConnectionPersistence> {
  const dataDirectory = options.dataDirectory ?? defaultEmailShieldDataDirectory();
  const databasePath = join(dataDirectory, DATABASE_FILENAME);
  const platform = options.platform ?? process.platform;
  const vault = options.credentialVault ?? createCredentialVault(platform);
  const databaseExists = existsSync(databasePath);

  if (!vault.capabilities().available || !vault.capabilities().persistent) {
    if (databaseExists) throw new Error("Encrypted live mailbox connections exist but their native credential-vault key is unavailable.");
    return new InMemoryLiveConnectionPersistence();
  }

  const resolved = await resolveDataBoundEncryptionKey({
    vault,
    legacyReference: KEY_REFERENCE,
    dataDirectory,
    platform,
    databaseExists,
    keyBytes: KEY_BYTES,
    label: "live connection",
    validateExistingKey: (candidate) => {
      new EncryptedFileLiveConnectionPersistence(dataDirectory, candidate).assertReadable();
    },
  });
  const persistence = new EncryptedFileLiveConnectionPersistence(dataDirectory, resolved.key);
  persistence.assertReadable();
  return persistence;
}
