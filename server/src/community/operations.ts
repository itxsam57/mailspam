import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  scryptSync,
  sign,
  verify,
} from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join } from "node:path";
import { EncryptedCommunityAggregateStore } from "./aggregateStore.js";
import { CommunityFeedSigner } from "./signing.js";
import {
  COMMUNITY_REPORT_DATABASE_FILE,
  COMMUNITY_REPORT_KEY_FILE,
  COMMUNITY_SIGNING_PRIVATE_FILE,
  COMMUNITY_SIGNING_PUBLIC_FILE,
} from "./storageFiles.js";

const BACKUP_VERSION = 1;
const BACKUP_AAD = Buffer.from("email-shield-community-backup-v1", "utf8");
const BACKUP_ALGORITHM = "aes-256-gcm";
const BACKUP_KDF = "scrypt";
const SCRYPT_N = 32_768;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_MAXMEM = 64 * 1024 * 1024;
const MAX_PASSPHRASE_FILE_BYTES = 4 * 1024;
const MIN_PASSPHRASE_BYTES = 16;
const MAX_SIGNING_KEY_FILE_BYTES = 64 * 1024;
export const MAX_COMMUNITY_BACKUP_SOURCE_BYTES = 192 * 1024 * 1024;
export const MAX_COMMUNITY_BACKUP_FILE_BYTES = 384 * 1024 * 1024;

const BACKUP_FILE_MODES: Readonly<Record<string, number>> = Object.freeze({
  [COMMUNITY_REPORT_KEY_FILE]: 0o600,
  [COMMUNITY_REPORT_DATABASE_FILE]: 0o600,
  [COMMUNITY_SIGNING_PRIVATE_FILE]: 0o600,
  [COMMUNITY_SIGNING_PUBLIC_FILE]: 0o644,
});

interface BackupFile {
  name: string;
  mode: number;
  sha256: string;
  content: string;
}

interface CommunityBackupPayload {
  version: 1;
  createdAt: string;
  files: BackupFile[];
}

interface CommunityBackupEnvelope {
  version: 1;
  kdf: { algorithm: "scrypt"; salt: string; N: number; r: number; p: number };
  cipher: { algorithm: "aes-256-gcm"; iv: string; authTag: string };
  ciphertext: string;
}

export interface CommunitySigningKeys {
  privatePem: string;
  publicPem: string;
}

export interface CommunityBackupResult {
  backupPath: string;
  createdAt: string;
  signingKeyId: string;
  aggregateStoragePresent: boolean;
  sourceBytes: number;
}

export interface CommunityRestoreResult {
  targetDataDirectory: string;
  createdAt: string;
  signingKeyId: string;
  aggregateStoragePresent: boolean;
}

export interface CommunityRotationManifest {
  version: 1;
  createdAt: string;
  currentKeyId: string;
  nextKeyId: string;
  currentPublicKey: string;
  nextPublicKey: string;
  sequence: [
    "deploy-overlap-trust",
    "verify-current-feed",
    "activate-next-signing-key",
    "verify-next-feed",
    "retire-current-trust-after-overlap",
  ];
}

export interface CommunityRotationResult {
  outputDirectory: string;
  currentKeyId: string;
  nextKeyId: string;
  manifestPath: string;
  nextPrivateKeyPath: string;
  nextPublicKeyPath: string;
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function onlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const accepted = new Set(allowed);
  return Object.keys(value).every((key) => accepted.has(key));
}

function sha256(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function signingKeyId(publicPem: string): string {
  const publicKey = createPublicKey(publicPem);
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("Community signing public key must be Ed25519.");
  const der = publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex").slice(0, 24);
}

function validateSigningKeyPair(keys: CommunitySigningKeys): string {
  const privateKey = createPrivateKey(keys.privatePem);
  const publicKey = createPublicKey(keys.publicPem);
  if (privateKey.asymmetricKeyType !== "ed25519" || publicKey.asymmetricKeyType !== "ed25519") {
    throw new Error("Community signing keys must be Ed25519 keys.");
  }
  const challenge = Buffer.from("email-shield-community-operations-key-validation-v1", "utf8");
  const signature = sign(null, challenge, privateKey);
  if (!verify(null, challenge, publicKey, signature)) {
    throw new Error("Community signing private and public keys do not match.");
  }
  return signingKeyId(keys.publicPem);
}

function safeReadFile(
  path: string,
  description: string,
  maxBytes: number,
  requireOwnerOnly = false,
): Buffer {
  const noFollow = process.platform === "win32" ? 0 : constants.O_NOFOLLOW;
  let descriptor: number;
  try {
    descriptor = openSync(path, constants.O_RDONLY | noFollow);
  } catch {
    throw new Error(`${description} could not be opened safely.`);
  }
  try {
    const stat = fstatSync(descriptor);
    if (!stat.isFile()) throw new Error(`${description} must be a regular file.`);
    if (requireOwnerOnly && process.platform !== "win32" && (stat.mode & 0o077) !== 0) {
      throw new Error(`${description} must not be accessible by group or other users.`);
    }
    if (stat.size < 0 || stat.size > maxBytes) throw new Error(`${description} exceeds its recovery size limit.`);
    const content = readFileSync(descriptor);
    if (content.length > maxBytes) {
      content.fill(0);
      throw new Error(`${description} exceeded its recovery size limit while being read.`);
    }
    return content;
  } finally {
    closeSync(descriptor);
  }
}

function loadSigningKeys(
  dataDirectory: string,
  configured?: CommunitySigningKeys,
): { keys: CommunitySigningKeys; keyId: string } {
  if (configured) return { keys: configured, keyId: validateSigningKeyPair(configured) };
  const privatePath = join(dataDirectory, COMMUNITY_SIGNING_PRIVATE_FILE);
  const publicPath = join(dataDirectory, COMMUNITY_SIGNING_PUBLIC_FILE);
  const hasPrivate = existsSync(privatePath);
  const hasPublic = existsSync(publicPath);
  if (hasPrivate !== hasPublic) throw new Error("Community signing key storage is incomplete.");
  if (!hasPrivate) throw new Error("Community signing key pair is missing; initialize the service or provide configured signing keys.");

  const privateBytes = safeReadFile(privatePath, "Community signing private key", MAX_SIGNING_KEY_FILE_BYTES);
  const publicBytes = safeReadFile(publicPath, "Community signing public key", MAX_SIGNING_KEY_FILE_BYTES);
  try {
    const keys = {
      privatePem: privateBytes.toString("utf8"),
      publicPem: publicBytes.toString("utf8"),
    };
    return { keys, keyId: validateSigningKeyPair(keys) };
  } finally {
    privateBytes.fill(0);
    publicBytes.fill(0);
  }
}

function passphraseBuffer(passphrase: string | Buffer): Buffer {
  const value = Buffer.isBuffer(passphrase) ? Buffer.from(passphrase) : Buffer.from(passphrase, "utf8");
  if (value.length < MIN_PASSPHRASE_BYTES || value.length > MAX_PASSPHRASE_FILE_BYTES) {
    value.fill(0);
    throw new Error(`Community backup passphrase must be between ${MIN_PASSPHRASE_BYTES} and ${MAX_PASSPHRASE_FILE_BYTES} bytes.`);
  }
  return value;
}

function deriveBackupKey(passphrase: Buffer, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, 32, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAXMEM,
  });
}

function parseJson<T>(raw: string, description: string): T {
  try {
    return JSON.parse(raw) as T;
  } catch {
    throw new Error(`${description} contains invalid JSON.`);
  }
}

function canonicalBase64(value: unknown, expectedBytes?: number): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new Error("Community backup contains invalid base64 encoding.");
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value || (expectedBytes !== undefined && decoded.length !== expectedBytes)) {
    decoded.fill(0);
    throw new Error("Community backup contains non-canonical cryptographic encoding.");
  }
  return decoded;
}

function encodeBackupFile(name: string, content: Buffer): BackupFile {
  return {
    name,
    mode: BACKUP_FILE_MODES[name]!,
    sha256: sha256(content),
    content: content.toString("base64"),
  };
}

function decodeBackupFile(value: unknown): { name: string; content: Buffer } {
  const file = record(value);
  if (!file || !onlyKeys(file, ["name", "mode", "sha256", "content"])) {
    throw new Error("Community backup contains an invalid file entry.");
  }
  if (typeof file.name !== "string" || !Object.hasOwn(BACKUP_FILE_MODES, file.name)) {
    throw new Error("Community backup contains an unexpected file name.");
  }
  if (file.mode !== BACKUP_FILE_MODES[file.name]) throw new Error("Community backup contains an invalid file mode.");
  if (typeof file.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(file.sha256)) {
    throw new Error("Community backup contains an invalid file digest.");
  }
  const content = canonicalBase64(file.content);
  if (sha256(content) !== file.sha256) {
    content.fill(0);
    throw new Error("Community backup file integrity validation failed.");
  }
  return { name: file.name, content };
}

function validatePayload(value: unknown): { payload: CommunityBackupPayload; files: Map<string, Buffer> } {
  const payload = record(value);
  if (!payload || !onlyKeys(payload, ["version", "createdAt", "files"]) || payload.version !== 1) {
    throw new Error("Community backup payload is invalid.");
  }
  if (typeof payload.createdAt !== "string" || payload.createdAt.length > 64 || !Number.isFinite(Date.parse(payload.createdAt))) {
    throw new Error("Community backup creation timestamp is invalid.");
  }
  if (!Array.isArray(payload.files) || payload.files.length < 2 || payload.files.length > 4) {
    throw new Error("Community backup file manifest is invalid.");
  }

  const files = new Map<string, Buffer>();
  let totalBytes = 0;
  try {
    for (const fileValue of payload.files) {
      const { name, content } = decodeBackupFile(fileValue);
      if (files.has(name)) {
        content.fill(0);
        throw new Error("Community backup contains duplicate file entries.");
      }
      totalBytes += content.length;
      if (totalBytes > MAX_COMMUNITY_BACKUP_SOURCE_BYTES) {
        content.fill(0);
        throw new Error("Community backup payload exceeds the recovery size limit.");
      }
      files.set(name, content);
    }

    const hasStorageKey = files.has(COMMUNITY_REPORT_KEY_FILE);
    const hasDatabase = files.has(COMMUNITY_REPORT_DATABASE_FILE);
    if (hasStorageKey !== hasDatabase) throw new Error("Community backup aggregate storage pair is incomplete.");
    if (!files.has(COMMUNITY_SIGNING_PRIVATE_FILE) || !files.has(COMMUNITY_SIGNING_PUBLIC_FILE)) {
      throw new Error("Community backup signing key pair is incomplete.");
    }

    return { payload: payload as unknown as CommunityBackupPayload, files };
  } catch (error) {
    for (const content of files.values()) content.fill(0);
    throw error;
  }
}

function validateRecoveryDirectory(dataDirectory: string): { signingKeyId: string; aggregateStoragePresent: boolean } {
  const signer = new CommunityFeedSigner(dataDirectory);
  const hasStorageKey = existsSync(join(dataDirectory, COMMUNITY_REPORT_KEY_FILE));
  const hasDatabase = existsSync(join(dataDirectory, COMMUNITY_REPORT_DATABASE_FILE));
  if (hasStorageKey !== hasDatabase) throw new Error("Recovered community aggregate storage pair is incomplete.");
  if (hasStorageKey) {
    const store = new EncryptedCommunityAggregateStore(dataDirectory);
    store.stats();
    store.buildFeedPayload();
  }
  return { signingKeyId: signer.keyId, aggregateStoragePresent: hasStorageKey };
}

export function createEncryptedCommunityBackup(options: {
  dataDirectory: string;
  backupPath: string;
  passphrase: string | Buffer;
  configuredSigningKeys?: CommunitySigningKeys;
  now?: Date;
}): CommunityBackupResult {
  if (existsSync(options.backupPath)) throw new Error("Community backup destination already exists; refusing to overwrite it.");
  const signing = loadSigningKeys(options.dataDirectory, options.configuredSigningKeys);
  const storageKeyPath = join(options.dataDirectory, COMMUNITY_REPORT_KEY_FILE);
  const databasePath = join(options.dataDirectory, COMMUNITY_REPORT_DATABASE_FILE);
  const hasStorageKey = existsSync(storageKeyPath);
  const hasDatabase = existsSync(databasePath);
  if (hasStorageKey !== hasDatabase) throw new Error("Community aggregate storage is incomplete; refusing to back up an inconsistent state.");
  if (hasStorageKey) {
    const store = new EncryptedCommunityAggregateStore(options.dataDirectory);
    store.stats();
    store.buildFeedPayload();
  }

  const privateBytes = Buffer.from(signing.keys.privatePem, "utf8");
  const publicBytes = Buffer.from(signing.keys.publicPem, "utf8");
  let remainingBytes = MAX_COMMUNITY_BACKUP_SOURCE_BYTES - privateBytes.length - publicBytes.length;
  if (remainingBytes < 0) {
    privateBytes.fill(0);
    throw new Error("Community signing keys exceed the portable backup size limit.");
  }

  const files: BackupFile[] = [];
  let sourceBytes = privateBytes.length + publicBytes.length;
  try {
    if (hasStorageKey) {
      const storageKey = safeReadFile(storageKeyPath, "Community aggregate storage key", remainingBytes);
      remainingBytes -= storageKey.length;
      const database = safeReadFile(databasePath, "Community aggregate database", remainingBytes);
      try {
        sourceBytes += storageKey.length + database.length;
        files.push(encodeBackupFile(COMMUNITY_REPORT_KEY_FILE, storageKey));
        files.push(encodeBackupFile(COMMUNITY_REPORT_DATABASE_FILE, database));
      } finally {
        storageKey.fill(0);
        database.fill(0);
      }
    }
    files.push(encodeBackupFile(COMMUNITY_SIGNING_PRIVATE_FILE, privateBytes));
    files.push(encodeBackupFile(COMMUNITY_SIGNING_PUBLIC_FILE, publicBytes));
  } finally {
    privateBytes.fill(0);
  }

  const createdAt = (options.now ?? new Date()).toISOString();
  const plaintext = Buffer.from(JSON.stringify({ version: 1, createdAt, files } satisfies CommunityBackupPayload), "utf8");
  const passphrase = passphraseBuffer(options.passphrase);
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = deriveBackupKey(passphrase, salt);
  try {
    const cipher = createCipheriv(BACKUP_ALGORITHM, key, iv);
    cipher.setAAD(BACKUP_AAD);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const envelope: CommunityBackupEnvelope = {
      version: BACKUP_VERSION,
      kdf: { algorithm: BACKUP_KDF, salt: salt.toString("base64"), N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P },
      cipher: { algorithm: BACKUP_ALGORITHM, iv: iv.toString("base64"), authTag: cipher.getAuthTag().toString("base64") },
      ciphertext: ciphertext.toString("base64"),
    };
    const serialized = JSON.stringify(envelope);
    if (Buffer.byteLength(serialized, "utf8") > MAX_COMMUNITY_BACKUP_FILE_BYTES) {
      throw new Error("Encrypted community backup exceeds the portable backup file limit.");
    }
    mkdirSync(dirname(options.backupPath), { recursive: true, mode: 0o700 });
    writeFileSync(options.backupPath, serialized, { flag: "wx", mode: 0o600 });
    try { chmodSync(options.backupPath, 0o600); } catch {}
  } finally {
    plaintext.fill(0);
    key.fill(0);
    passphrase.fill(0);
  }

  return {
    backupPath: options.backupPath,
    createdAt,
    signingKeyId: signing.keyId,
    aggregateStoragePresent: hasStorageKey,
    sourceBytes,
  };
}

function decryptBackup(
  backupPath: string,
  passphraseInput: string | Buffer,
): { payload: CommunityBackupPayload; files: Map<string, Buffer> } {
  if (!existsSync(backupPath)) throw new Error("Community backup file does not exist.");
  const stat = statSync(backupPath);
  if (!stat.isFile() || stat.size === 0 || stat.size > MAX_COMMUNITY_BACKUP_FILE_BYTES) {
    throw new Error("Community backup file exceeds the recovery size limit.");
  }
  const root = record(parseJson<unknown>(readFileSync(backupPath, "utf8"), "Community backup envelope"));
  if (!root || !onlyKeys(root, ["version", "kdf", "cipher", "ciphertext"]) || root.version !== BACKUP_VERSION) {
    throw new Error("Community backup envelope is invalid.");
  }
  const kdf = record(root.kdf);
  const cipherMetadata = record(root.cipher);
  if (
    !kdf || !onlyKeys(kdf, ["algorithm", "salt", "N", "r", "p"]) ||
    kdf.algorithm !== BACKUP_KDF || kdf.N !== SCRYPT_N || kdf.r !== SCRYPT_R || kdf.p !== SCRYPT_P ||
    !cipherMetadata || !onlyKeys(cipherMetadata, ["algorithm", "iv", "authTag"]) ||
    cipherMetadata.algorithm !== BACKUP_ALGORITHM
  ) throw new Error("Community backup envelope parameters are unsupported.");

  const salt = canonicalBase64(kdf.salt, 16);
  const iv = canonicalBase64(cipherMetadata.iv, 12);
  const authTag = canonicalBase64(cipherMetadata.authTag, 16);
  const ciphertext = canonicalBase64(root.ciphertext);
  const passphrase = passphraseBuffer(passphraseInput);
  const key = deriveBackupKey(passphrase, salt);
  let plaintext: Buffer;
  try {
    const decipher = createDecipheriv(BACKUP_ALGORITHM, key, iv);
    decipher.setAAD(BACKUP_AAD);
    decipher.setAuthTag(authTag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error("Community backup authentication failed; passphrase or backup content is invalid.");
  } finally {
    key.fill(0);
    passphrase.fill(0);
    salt.fill(0);
    iv.fill(0);
    authTag.fill(0);
    ciphertext.fill(0);
  }

  try {
    return validatePayload(parseJson<unknown>(plaintext.toString("utf8"), "Community backup payload"));
  } finally {
    plaintext.fill(0);
  }
}

export function restoreEncryptedCommunityBackup(options: {
  backupPath: string;
  targetDataDirectory: string;
  passphrase: string | Buffer;
}): CommunityRestoreResult {
  if (existsSync(options.targetDataDirectory)) {
    throw new Error("Community restore target already exists; restore requires a new path for atomic cutover.");
  }
  const { payload, files } = decryptBackup(options.backupPath, options.passphrase);
  const parent = dirname(options.targetDataDirectory);
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const staging = mkdtempSync(join(parent, `.${basename(options.targetDataDirectory)}.restore-`));
  try {
    for (const [name, content] of files) {
      const path = join(staging, name);
      writeFileSync(path, content, { flag: "wx", mode: BACKUP_FILE_MODES[name]! });
      try { chmodSync(path, BACKUP_FILE_MODES[name]!); } catch {}
    }
    const validation = validateRecoveryDirectory(staging);
    if (existsSync(options.targetDataDirectory)) throw new Error("Community restore target appeared during validation; refusing non-atomic overwrite.");
    renameSync(staging, options.targetDataDirectory);
    return {
      targetDataDirectory: options.targetDataDirectory,
      createdAt: payload.createdAt,
      signingKeyId: validation.signingKeyId,
      aggregateStoragePresent: validation.aggregateStoragePresent,
    };
  } catch (error) {
    rmSync(staging, { recursive: true, force: true });
    throw error;
  } finally {
    for (const content of files.values()) content.fill(0);
  }
}

export function readCommunityBackupPassphraseFile(path: string): Buffer {
  if (!existsSync(path)) throw new Error("Community backup passphrase file does not exist.");
  const raw = safeReadFile(path, "Community backup passphrase file", MAX_PASSPHRASE_FILE_BYTES, true);
  if (raw.length === 0) {
    raw.fill(0);
    throw new Error("Community backup passphrase file must not be empty.");
  }
  let end = raw.length;
  while (end > 0 && (raw[end - 1] === 0x0a || raw[end - 1] === 0x0d)) end--;
  const trimmed = Buffer.from(raw.subarray(0, end));
  raw.fill(0);
  try {
    return passphraseBuffer(trimmed);
  } finally {
    trimmed.fill(0);
  }
}

function generateSigningKeys(): CommunitySigningKeys {
  const pair = generateKeyPairSync("ed25519");
  return {
    privatePem: pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

export function prepareCommunitySigningRotation(options: {
  dataDirectory: string;
  outputDirectory: string;
  configuredCurrentSigningKeys?: CommunitySigningKeys;
  now?: Date;
}): CommunityRotationResult {
  if (existsSync(options.outputDirectory)) throw new Error("Community signing rotation output already exists; refusing to overwrite it.");
  const current = loadSigningKeys(options.dataDirectory, options.configuredCurrentSigningKeys);
  const next = generateSigningKeys();
  const nextKeyId = validateSigningKeyPair(next);
  if (nextKeyId === current.keyId) throw new Error("Generated signing key unexpectedly matches the active key.");

  const createdAt = (options.now ?? new Date()).toISOString();
  const manifest: CommunityRotationManifest = {
    version: 1,
    createdAt,
    currentKeyId: current.keyId,
    nextKeyId,
    currentPublicKey: current.keys.publicPem,
    nextPublicKey: next.publicPem,
    sequence: [
      "deploy-overlap-trust",
      "verify-current-feed",
      "activate-next-signing-key",
      "verify-next-feed",
      "retire-current-trust-after-overlap",
    ],
  };

  const parent = dirname(options.outputDirectory);
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const staging = mkdtempSync(join(parent, `.${basename(options.outputDirectory)}.rotation-`));
  const privatePath = join(staging, "next-private.pem");
  const publicPath = join(staging, "next-public.pem");
  const manifestPath = join(staging, "rotation-manifest.json");
  try {
    writeFileSync(privatePath, next.privatePem, { flag: "wx", mode: 0o600 });
    writeFileSync(publicPath, next.publicPem, { flag: "wx", mode: 0o644 });
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), { flag: "wx", mode: 0o644 });
    try { chmodSync(privatePath, 0o600); } catch {}
    const verified = verifyCommunitySigningRotationPackage(staging);
    if (verified.currentKeyId !== current.keyId || verified.nextKeyId !== nextKeyId) {
      throw new Error("Community signing rotation package self-verification failed.");
    }
    if (existsSync(options.outputDirectory)) throw new Error("Community signing rotation output appeared during preparation.");
    renameSync(staging, options.outputDirectory);
  } catch (error) {
    rmSync(staging, { recursive: true, force: true });
    throw error;
  }

  return {
    outputDirectory: options.outputDirectory,
    currentKeyId: current.keyId,
    nextKeyId,
    manifestPath: join(options.outputDirectory, "rotation-manifest.json"),
    nextPrivateKeyPath: join(options.outputDirectory, "next-private.pem"),
    nextPublicKeyPath: join(options.outputDirectory, "next-public.pem"),
  };
}

export function verifyCommunitySigningRotationPackage(directory: string): CommunityRotationManifest {
  const manifestPath = join(directory, "rotation-manifest.json");
  const privatePath = join(directory, "next-private.pem");
  const publicPath = join(directory, "next-public.pem");
  for (const path of [manifestPath, privatePath, publicPath]) {
    if (!existsSync(path) || !statSync(path).isFile()) throw new Error("Community signing rotation package is incomplete.");
  }
  const root = record(parseJson<unknown>(readFileSync(manifestPath, "utf8"), "Community rotation manifest"));
  if (!root || !onlyKeys(root, [
    "version", "createdAt", "currentKeyId", "nextKeyId", "currentPublicKey", "nextPublicKey", "sequence",
  ])) throw new Error("Community signing rotation manifest is invalid.");
  const expectedSequence: CommunityRotationManifest["sequence"] = [
    "deploy-overlap-trust",
    "verify-current-feed",
    "activate-next-signing-key",
    "verify-next-feed",
    "retire-current-trust-after-overlap",
  ];
  if (
    root.version !== 1 ||
    typeof root.createdAt !== "string" || root.createdAt.length > 64 || !Number.isFinite(Date.parse(root.createdAt)) ||
    typeof root.currentKeyId !== "string" || !/^[a-f0-9]{24}$/.test(root.currentKeyId) ||
    typeof root.nextKeyId !== "string" || !/^[a-f0-9]{24}$/.test(root.nextKeyId) ||
    root.currentKeyId === root.nextKeyId ||
    typeof root.currentPublicKey !== "string" || typeof root.nextPublicKey !== "string" ||
    !Array.isArray(root.sequence) || JSON.stringify(root.sequence) !== JSON.stringify(expectedSequence)
  ) throw new Error("Community signing rotation manifest is invalid.");

  const privateBytes = safeReadFile(privatePath, "Community rotation next private key", MAX_SIGNING_KEY_FILE_BYTES);
  const publicBytes = safeReadFile(publicPath, "Community rotation next public key", MAX_SIGNING_KEY_FILE_BYTES);
  try {
    const nextKeys = {
      privatePem: privateBytes.toString("utf8"),
      publicPem: publicBytes.toString("utf8"),
    };
    const nextKeyId = validateSigningKeyPair(nextKeys);
    if (nextKeyId !== root.nextKeyId || nextKeys.publicPem !== root.nextPublicKey) {
      throw new Error("Community signing rotation next-key material does not match its manifest.");
    }
  } finally {
    privateBytes.fill(0);
    publicBytes.fill(0);
  }
  if (signingKeyId(root.currentPublicKey) !== root.currentKeyId) {
    throw new Error("Community signing rotation current public key does not match its manifest.");
  }
  return root as unknown as CommunityRotationManifest;
}
