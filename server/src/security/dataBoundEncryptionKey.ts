import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { resolve } from "node:path";
import type { CredentialReference, CredentialVault } from "./credentialVault.js";

const DATA_BOUND_NAMESPACE = "email-shield-data-bound-credential-v1\0";

function normalizedDataDirectory(dataDirectory: string, platform: NodeJS.Platform): string {
  const absolute = resolve(dataDirectory).replaceAll("\\", "/");
  return platform === "win32" ? absolute.toLowerCase() : absolute;
}

/**
 * Native-vault records are bound to the local data root they encrypt. This
 * prevents a test, smoke run, alternate installation, or explicit
 * EMAIL_SHIELD_DATA_DIR from replacing the key for a user's normal profile.
 * Only a one-way digest enters visible vault metadata.
 */
export function dataBoundCredentialReference(
  legacyReference: CredentialReference,
  dataDirectory: string,
  platform: NodeJS.Platform = process.platform,
): CredentialReference {
  const digest = createHash("sha256")
    .update(DATA_BOUND_NAMESPACE, "utf8")
    .update(normalizedDataDirectory(dataDirectory, platform), "utf8")
    .digest("hex");
  return {
    kind: legacyReference.kind,
    id: `${legacyReference.id}:data:${digest}`,
  };
}

function decodeKey(secret: string, keyBytes: number, label: string): Buffer {
  const normalized = secret.trim();
  const key = Buffer.from(normalized, "base64");
  if (key.length !== keyBytes || key.toString("base64") !== normalized) {
    throw new Error(`Protected ${label} encryption key is invalid.`);
  }
  return key;
}

async function writeAndVerify(
  vault: CredentialVault,
  reference: CredentialReference,
  key: Buffer,
  label: string,
): Promise<void> {
  const encoded = key.toString("base64");
  await vault.write(reference, encoded);
  const stored = await vault.read(reference);
  if (!stored) throw new Error(`Protected ${label} encryption key write was not readable.`);
  const roundTrip = decodeKey(stored, key.length, label);
  if (!timingSafeEqual(roundTrip, key)) {
    throw new Error(`Protected ${label} encryption key verification failed.`);
  }
}

export interface ResolveDataBoundEncryptionKeyOptions {
  vault: CredentialVault;
  legacyReference: CredentialReference;
  dataDirectory: string;
  platform: NodeJS.Platform;
  databaseExists: boolean;
  keyBytes: number;
  label: string;
  validateExistingKey(key: Buffer): void;
}

export interface ResolvedDataBoundEncryptionKey {
  key: Buffer;
  reference: CredentialReference;
  migratedLegacyReference: boolean;
}

export class UnreadableEncryptedStateError extends Error {
  readonly code = "EMAIL_SHIELD_UNREADABLE_ENCRYPTED_STATE";

  constructor(readonly stateLabel: string) {
    super(
      `Encrypted ${stateLabel} state cannot be authenticated with its data-bound or legacy key. ` +
      "The encrypted file was preserved. Run `npm run recover:local-state` to archive unreadable state before starting clean.",
    );
    this.name = "UnreadableEncryptedStateError";
  }
}

/**
 * Resolves one data-root-scoped key. The old global reference is read only as
 * a migration candidate for an existing database and is accepted only after
 * authenticated decryption succeeds. It is never written or deleted here.
 */
export async function resolveDataBoundEncryptionKey(
  options: ResolveDataBoundEncryptionKeyOptions,
): Promise<ResolvedDataBoundEncryptionKey> {
  const {
    vault,
    legacyReference,
    dataDirectory,
    platform,
    databaseExists,
    keyBytes,
    label,
    validateExistingKey,
  } = options;
  const reference = dataBoundCredentialReference(legacyReference, dataDirectory, platform);
  const scopedSecret = await vault.read(reference);
  let scopedKey: Buffer | null = null;
  if (scopedSecret) {
    try {
      scopedKey = decodeKey(scopedSecret, keyBytes, label);
    } catch (error) {
      if (!databaseExists) throw error;
      // For an existing database, an invalid scoped record is only one failed
      // candidate. A valid authenticated legacy record may still recover it.
    }
  }

  if (scopedKey && !databaseExists) {
    return { key: scopedKey, reference, migratedLegacyReference: false };
  }
  if (scopedKey && databaseExists) {
    try {
      validateExistingKey(scopedKey);
      return { key: scopedKey, reference, migratedLegacyReference: false };
    } catch {
      // A pre-migration global key may still authenticate this database. It is
      // checked below before recovery is required.
    }
  }

  if (databaseExists) {
    const legacySecret = await vault.read(legacyReference);
    if (legacySecret) {
      try {
        const legacyKey = decodeKey(legacySecret, keyBytes, label);
        const isDifferent = !scopedKey || !timingSafeEqual(scopedKey, legacyKey);
        if (isDifferent) {
          validateExistingKey(legacyKey);
          await writeAndVerify(vault, reference, legacyKey, label);
          return { key: legacyKey, reference, migratedLegacyReference: true };
        }
      } catch {
        // Fail below with a stable recovery instruction. The encrypted file
        // and both vault records remain untouched.
      }
    }
    throw new UnreadableEncryptedStateError(label);
  }

  const key = randomBytes(keyBytes);
  await writeAndVerify(vault, reference, key, label);
  return { key, reference, migratedLegacyReference: false };
}
