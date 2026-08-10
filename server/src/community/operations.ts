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
  existsSync,
  mkdirSync,
  mkdtempSync,
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
export const MAX_COMMUNITY_BACKUP_SOURCE_BYTES = 256 * 1024 * 1024;
export const MAX_COMMUNITY_BACKUP_FILE_BYTES = 384 * 1024 * 1024;
const MAX_PASSPHRASE_FILE_BYTES = 4 * 1024;
const MIN_PASSPHRASE_BYTES = 16;

const BACKUP_FILE_MODES: Record<string, number> = {
  [COMMUNITY_REPORT_KEY_FILE]: 0o600,
  [COMMUNITY_REPORT_DATABASE_FILE]: 0o600,
  [COMMUNITY_SIGNING_PRIVATE_FILE]: 0o600,
  [COMMUNITY_SIGNING_PUBLIC_FILE]: 0o644,
};

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
  kdf: {
    algorithm: "scrypt";
    salt: string;
    N: number;
    r: number;
    p: number;
  };
  cipher: {
    algorithm: "aes-256-gcm";
    iv: string;
    authTag: string;
  };
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

function sha256(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function signingKeyId(publicPem: string): string {
  const der = createPublicKey(publicPem).export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex").slice(0, 24);
}

function validateSigningKeyPair(keys: CommunitySigningKeys): string {
  const challenge = Buffer.from("email-shield-community-operations-key-validation-v1", "utf8");
  const privateKey = createPrivateKey(keys.privatePem);
  const publicKey = createPublicKey(keys.publicPem);
  if (privateKey.asymmetricKeyType !== "ed25519" || publicKey.asymmetricKeyType !== "ed25519") {
    throw new Error("Community signing keys must be Ed25519 keys.");
  }
  const signature = sign(null, challenge, privateKey);
  if (!verify(null, challenge, publicKey, signature)) {
    throw new Error("Community signing private and public keys do not match.");
  }
  return signingKeyId(keys.publicPem);
}

function loadSigningKeys(dataDirectory: string, configured?: CommunitySigningKeys): { keys: CommunitySigningKeys; keyId: string } {
  if (configured) {
    return { keys: configured, keyId: validateSigningKeyPair(configured) };
  }
  const privatePath = join(dataDirectory, COMMUNITY_SIGNING_PRIVATE_FILE);
  const publicPath = join(dataDirectory, COMMUNITY_SIGNING_PUBLIC_FILE);
  if (!existsSync(privatePath) || !existsSync(publicPath)) {
    throw new Error("Community signing key pair is missing; initialize the service or provide configured signing keys.");
  }
  const keys = {
    privatePem: readFileSync(privatePath, "utf8"),
    publicPem: readFileSync(publicPath, "utf8"),
  };
  return { keys, keyId: validateSigningKeyPair(keys) };
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

function safeJsonParse<T>(raw: string, description: string): T {
  try {
    return JSON.parse(raw) as T;
  } catch {
    throw new Error(`${description} contains invalid JSON.`);
  }
}

function validateBackupFile(file: BackupFile): Buffer {
  if (!file || typeof file !== "object") throw new Error("Community backup contains an invalid file entry.");
  if (!Object.hasOwn(BACKUP_FILE_MODES, file.name)) throw new Error("Community backup contains an unexpected file name.");
  if (file.mode !== BACKUP_FILE_MODES[file.name]) throw new Error("Community backup contains an invalid file mode.");
  if (!/^[a-f0-9]{64}$/.test(file.sha256)) throw new Error("Community backup contains an invalid file digest.");
  if (typeof file.content !== "string" || !/^[A-Za-z0-9+/]*={0,2}$/.test(file.content)) {
    throw new Error("Community backup contains invalid file encoding.");
  }
  const content = Buffer.from(file.content, "base64");
  if (content.toString("base64") !== file.content || sha256(content) !== file.sha256) {
    throw new Error("Community backup file integrity validation failed.");
  }
  return content;
}

function validatePayload(payload: CommunityBackupPayload): Map<string, Buffer> {
  if (!payload || payload.version !== 1 || typeof payload.createdAt !== "string" || !Number.isFinite(Date.parse(payload.createdAt))) {
    throw new Error("Community backup payload is invalid.");
  }
  if (!Array.isArray(payload.files) || payload.files.length < 2 || payload.files.length > 4) {
    throw new Error("Community backup file manifest is invalid.");
  }
  const files = new Map<string, Buffer>();
  let totalBytes = 0;
  for (const file of payload.files) {
    if (files.has(file.name)) throw new Error("Community backup contains duplicate file entries.");
    const content = validateBackupFile(file);
    totalBytes += content.length;
    if (totalBytes > MAX_COMMUNITY_BACKUP_SOURCE_BYTES) throw new Error("Community backup payload exceeds the recovery size limit.");
    files.set(file.name, content);
  }

  const hasStorageKey = files.has(COMMUNITY_REPORT_KEY_FILE);
  const hasDatabase = files.has(COMMUNITY_REPORT_DATABASE_FILE);
  if (hasStorageKey !== hasDatabase) throw new Error("Community backup aggregate storage pair is incomplete.");
  if (!files.has(COMMUNITY_SIGNING_PRIVATE_FILE) || !files.has(COMMUNITY_SIGNING_PUBLIC_FILE)) {
    throw new Error("Community backup signing key pair is incomplete.");
  }
  return files;
}

function validateRecoveryDirectory(dataDirectory: string): { signingKeyId: string; aggregateStoragePresent: boolean } {
  const signer = new CommunityFeedSigner(dataDirectory);
  const keyId = signer.keyId;
  const hasStorageKey = existsSync(join(dataDirectory, COMMUNITY_REPORT_KEY_FILE));
  const hasDatabase = existsSync(join(dataDirectory, COMMUNITY_REPORT_DATABASE_FILE));
  if (hasStorageKey !== hasDatabase) throw new Error("Recovered community aggregate storage pair is incomplete.");
  if (hasStorageKey) {
    const store = new EncryptedCommunityAggregateStore(dataDirectory);
    store.stats();
    store.buildFeedPayload();
  }
  return { signingKeyId: keyId, aggregateStoragePresent: hasStorageKey };
}

function readSourceFile(path: string, name: string): BackupFile {
  const stat = statSync(path);
  if (!stat.isFile()) throw new Error(`Community authoritative file ${name} is not a regular file.`);
  const content = readFileSync(path);
  return {
    name,
    mode: BACKUP_FILE_MODES[name]!,
    sha256: sha256(content),
    content: content.toString("base64"),
  };
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

  const files: BackupFile[] = [];
  if (hasStorageKey) {
    files.push(readSourceFile(storageKeyPath, COMMUNITY_REPORT_KEY_FILE));
    files.push(readSourceFile(databasePath, COMMUNITY_REPORT_DATABASE_FILE));
  }
  const privateBytes = Buffer.from(signing.keys.privatePem, "utf8");
  const publicBytes = Buffer.from(signing.keys.publicPem, "utf8");
  files.push({
    name: COMMUNITY_SIGNING_PRIVATE_FILE,
    mode: BACKUP_FILE_MODES[COMMUNITY_SIGNING_PRIVATE_FILE]!,
    sha256: sha256(privateBytes),
    content: privateBytes.toString("base64"),
  });
  files.push({
    name: COMMUNITY_SIGNING_PUBLIC_FILE,
    mode: BACKUP_FILE_MODES[COMMUNITY_SIGNING_PUBLIC_FILE]!,
    sha256: sha256(publicBytes),
    content: publicBytes.toString("base64"),
  });
  privateBytes.fill(0);

  const sourceBytes = files.reduce((sum, file) => sum + Buffer.byteLength(file.content, "base64"), 0);
  if (sourceBytes > MAX_COMMUNITY_BACKUP_SOURCE_BYTES) throw new Error("Community authoritative data exceeds the portable backup size limit.");

  const createdAt = (options.now ?? new Date()).toISOString();
  const payload: CommunityBackupPayload = { version: 1, createdAt, files };
  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
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

function decryptBackup(backupPath: string, passphraseInput: string | Buffer): { payload: CommunityBackupPayload; files: Map<string, Buffer> } {
  const stat = statSync(backupPath);
  if (!stat.isFile() || stat.size > MAX_COMMUNITY_BACKUP_FILE_BYTES) throw new Error("Community backup file is missing or exceeds the recovery size limit.");
  const envelope = safeJsonParse<CommunityBackupEnvelope>(readFileSync(backupPath, "utf8"), "Community backup envelope");
  if (
    envelope?.version !== BACKUP_VERSION ||
    envelope.kdf?.algorithm !== BACKUP_KDF ||
    envelope.kdf.N !== SCRYPT_N || envelope.kdf.r !== SCRYPT_R || envelope.kdf.p !== SCRYPT_P ||
    envelope.cipher?.algorithm !== BACKUP_ALGORITHM
  ) throw new Error("Community backup envelope parameters are unsupported.");

  const salt = Buffer.from(envelope.kdf.salt, "base64");
  const iv = Buffer.from(envelope.cipher.iv, "base64");
  const authTag = Buffer.from(envelope.cipher.authTag, "base64");
  const ciphertext = Buffer.from(envelope.ciphertext, "base64");
  if (salt.length !== 16 || iv.length !== 12 || authTag.length !== 16) throw new Error("Community backup cryptographic metadata is invalid.");
  if (
    salt.toString("base64") !== envelope.kdf.salt ||
    iv.toString("base64") !== envelope.cipher.iv ||
    authTag.toString("base64") !== envelope.cipher.authTag ||
    ciphertext.toString("base64") !== envelope.ciphertext
  ) throw new Error("Community backup encoding is invalid.");

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
  }
  try {
    const payload = safeJsonParse<CommunityBackupPayload>(plaintext.toString("utf8"), "Community backup payload");
    const files = validatePayload(payload);
    return { payload, files };
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
    throw new Error("Community restore target already exists; restore requires a new empty path for atomic cutover.");
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
  const stat = statSync(path);
  if (!stat.isFile() || stat.size === 0 || stat.size > MAX_PASSPHRASE_FILE_BYTES) {
    throw new Error("Community backup passphrase file must be a small regular file.");
  }
  const raw = readFileSync(path);
  while (raw.length > 0 && (raw[raw.length - 1] === 0x0a || raw[raw.length - 1] === 0x0d)) {
    raw.fill(0, raw.length - 1);
    const trimmed = Buffer.from(raw.subarray(0, raw.length - 1));
    raw.fill(0);
    return passphraseBuffer(trimmed);
  }
  return passphraseBuffer(raw);
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
    renameSync(staging, options.outputDirectory);
  } catch (error) {
    rmSync(staging, { recursive: true, force: true });
    throw error;
  } finally {
    Buffer.from(next.privatePem, "utf8").fill(0);
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
  const manifest = safeJsonParse<CommunityRotationManifest>(readFileSync(manifestPath, "utf8"), "Community rotation manifest");
  const expectedSequence: CommunityRotationManifest["sequence"] = [
    "deploy-overlap-trust",
    "verify-current-feed",
    "activate-next-signing-key",
    "verify-next-feed",
    "retire-current-trust-after-overlap",
  ];
  if (
    manifest?.version !== 1 ||
    typeof manifest.createdAt !== "string" || !Number.isFinite(Date.parse(manifest.createdAt)) ||
    !/^[a-f0-9]{24}$/.test(manifest.currentKeyId) ||
    !/^[a-f0-9]{24}$/.test(manifest.nextKeyId) ||
    manifest.currentKeyId === manifest.nextKeyId ||
    JSON.stringify(manifest.sequence) !== JSON.stringify(expectedSequence)
  ) throw new Error("Community signing rotation manifest is invalid.");

  const nextKeys = {
    privatePem: readFileSync(privatePath, "utf8"),
    publicPem: readFileSync(publicPath, "utf8"),
  };
  const nextKeyId = validateSigningKeyPair(nextKeys);
  if (nextKeyId !== manifest.nextKeyId || nextKeys.publicPem !== manifest.nextPublicKey) {
    throw new Error("Community signing rotation next-key material does not match its manifest.");
  }
  if (signingKeyId(manifest.currentPublicKey) !== manifest.currentKeyId) {
    throw new Error("Community signing rotation current public key does not match its manifest.");
  }
  return manifest;
}
