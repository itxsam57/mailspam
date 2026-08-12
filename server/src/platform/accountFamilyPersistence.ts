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
import type { AccountPlatformRepository } from "./accountFamilyPorts.js";
import {
  ACCOUNT_PLATFORM_SCHEMA_VERSION,
  MAX_ACCOUNT_DEVICES,
  MAX_FAMILY_INVITES,
  MAX_FAMILY_MEMBERS,
  MAX_FAMILY_THREAT_CAMPAIGNS,
  emptyAccountPlatformState,
  normalizeDeviceLabel,
  normalizePublicKeySpki,
  normalizeUsername,
  type AccountPlatformState,
  type EmailShieldAccount,
  type FamilyCircle,
  type MailboxAccountLink,
  type VerifiedEntitlement,
} from "./accountFamilyTypes.js";

const DATABASE_VERSION = 1;
const ALGORITHM = "aes-256-gcm";
const AAD = Buffer.from("email-shield-account-family-v1", "utf8");
const KEY_BYTES = 32;
const MAX_DATABASE_BYTES = 2 * 1024 * 1024;
const MAX_ACCOUNTS = 128;
const MAX_FAMILY_CIRCLES = 64;
const MAX_MAILBOX_LINKS = 256;
export const ACCOUNT_PLATFORM_ENCRYPTED_DATABASE_MAX_BYTES = encryptedJsonEnvelopeByteCeiling(MAX_DATABASE_BYTES);

const KEY_REFERENCE: CredentialReference = {
  id: "account-family-encryption-key-v1",
  kind: "local-encryption-key",
};

interface EncryptedAccountPlatformEnvelope {
  version: 1;
  algorithm: "aes-256-gcm";
  iv: string;
  authTag: string;
  ciphertext: string;
}

export interface AccountPlatformRepositoryFactoryOptions {
  dataDirectory?: string;
  credentialVault?: CredentialVault;
  platform?: NodeJS.Platform;
}

function cloneState(state: AccountPlatformState): AccountPlatformState {
  return structuredClone(state);
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object.`);
  return value as Record<string, unknown>;
}

function onlyFields(value: Record<string, unknown>, fields: readonly string[], label: string): void {
  const known = new Set(fields);
  if (Object.keys(value).some((field) => !known.has(field))) throw new Error(`${label} contains unknown fields.`);
}

function safeTimestamp(value: unknown, nullable = false): value is number | null {
  return (nullable && value === null) || (Number.isSafeInteger(value) && Number(value) > 0);
}

function id(value: unknown, prefix: string): string {
  if (typeof value !== "string" || !new RegExp(`^${prefix}_[A-Za-z0-9_-]{8,160}$`).test(value)) {
    throw new Error(`${prefix} identifier is invalid.`);
  }
  return value;
}

function hash(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw new Error(`${label} hash is invalid.`);
  return value;
}

function normalizeEntitlement(input: unknown): VerifiedEntitlement {
  const value = object(input, "Entitlement");
  onlyFields(value, [
    "plan", "status", "source", "productId", "storeAccountReference", "verifiedAt", "expiresAt", "graceUntil", "seatLimit",
  ], "Entitlement");
  if (!["free", "individual", "family"].includes(String(value.plan))) throw new Error("Entitlement plan is invalid.");
  if (!["active", "grace", "expired", "revoked"].includes(String(value.status))) throw new Error("Entitlement status is invalid.");
  if (!["development", "apple", "google", "web"].includes(String(value.source))) throw new Error("Entitlement source is invalid.");
  if (typeof value.productId !== "string" || value.productId.length < 1 || value.productId.length > 128) throw new Error("Entitlement product ID is invalid.");
  if (value.storeAccountReference !== null && (typeof value.storeAccountReference !== "string" || value.storeAccountReference.length < 8 || value.storeAccountReference.length > 256)) {
    throw new Error("Entitlement store reference is invalid.");
  }
  if (!safeTimestamp(value.verifiedAt) || !safeTimestamp(value.expiresAt, true) || !safeTimestamp(value.graceUntil, true)) {
    throw new Error("Entitlement timestamps are invalid.");
  }
  if (!Number.isSafeInteger(value.seatLimit) || Number(value.seatLimit) < 1 || Number(value.seatLimit) > MAX_FAMILY_MEMBERS) {
    throw new Error("Entitlement seat limit is invalid.");
  }
  if (value.plan !== "family" && value.seatLimit !== 1) throw new Error("Non-family plans must have exactly one seat.");
  if (value.plan === "family" && Number(value.seatLimit) < 2) throw new Error("Family entitlement requires at least two seats.");
  return structuredClone(value) as unknown as VerifiedEntitlement;
}

function normalizeAccount(input: unknown): EmailShieldAccount {
  const value = object(input, "Email Shield account");
  onlyFields(value, ["accountId", "username", "createdAt", "recoveryCodeHash", "devices", "entitlement", "familyCircleId"], "Email Shield account");
  const accountId = id(value.accountId, "acct");
  const username = normalizeUsername(value.username);
  if (!safeTimestamp(value.createdAt)) throw new Error("Account creation time is invalid.");
  const recoveryCodeHash = hash(value.recoveryCodeHash, "Recovery code");
  if (!Array.isArray(value.devices) || value.devices.length < 1 || value.devices.length > MAX_ACCOUNT_DEVICES) throw new Error("Account device list is invalid.");
  const devices = value.devices.map((raw) => {
    const device = object(raw, "Registered device");
    onlyFields(device, ["deviceId", "algorithm", "publicKeySpki", "platform", "label", "createdAt", "lastSeenAt", "revokedAt"], "Registered device");
    const deviceId = typeof device.deviceId === "string" && /^dev_[a-f0-9]{64}$/.test(device.deviceId) ? device.deviceId : null;
    if (!deviceId) throw new Error("Registered device ID is invalid.");
    if (!["p256", "ed25519"].includes(String(device.algorithm))) throw new Error("Registered device algorithm is invalid.");
    const publicKeySpki = normalizePublicKeySpki(device.publicKeySpki);
    if (!["desktop", "ios", "android"].includes(String(device.platform))) throw new Error("Registered device platform is invalid.");
    const label = normalizeDeviceLabel(device.label);
    if (!safeTimestamp(device.createdAt) || !safeTimestamp(device.lastSeenAt) || !safeTimestamp(device.revokedAt, true)) throw new Error("Registered device timestamps are invalid.");
    return {
      deviceId,
      algorithm: device.algorithm as "p256" | "ed25519",
      publicKeySpki,
      platform: device.platform as "desktop" | "ios" | "android",
      label,
      createdAt: Number(device.createdAt),
      lastSeenAt: Number(device.lastSeenAt),
      revokedAt: device.revokedAt === null ? null : Number(device.revokedAt),
    };
  });
  if (new Set(devices.map((device) => device.deviceId)).size !== devices.length) throw new Error("Account contains duplicate device IDs.");
  const familyCircleId = value.familyCircleId === null ? null : id(value.familyCircleId, "family");
  return {
    accountId,
    username,
    createdAt: Number(value.createdAt),
    recoveryCodeHash,
    devices,
    entitlement: normalizeEntitlement(value.entitlement),
    familyCircleId,
  };
}

function normalizeFamilyCircle(input: unknown): FamilyCircle {
  const value = object(input, "Family Shield circle");
  onlyFields(value, ["familyCircleId", "ownerAccountId", "createdAt", "strictProtection", "members", "invitations", "threats"], "Family Shield circle");
  const familyCircleId = id(value.familyCircleId, "family");
  const ownerAccountId = id(value.ownerAccountId, "acct");
  if (!safeTimestamp(value.createdAt) || typeof value.strictProtection !== "boolean") throw new Error("Family Shield circle metadata is invalid.");
  if (!Array.isArray(value.members) || value.members.length < 1 || value.members.length > MAX_FAMILY_MEMBERS) throw new Error("Family Shield member list is invalid.");
  const members = value.members.map((raw) => {
    const member = object(raw, "Family Shield member");
    onlyFields(member, ["accountId", "role", "joinedAt"], "Family Shield member");
    if (!["owner", "member"].includes(String(member.role)) || !safeTimestamp(member.joinedAt)) throw new Error("Family Shield member metadata is invalid.");
    return { accountId: id(member.accountId, "acct"), role: member.role as "owner" | "member", joinedAt: Number(member.joinedAt) };
  });
  if (new Set(members.map((member) => member.accountId)).size !== members.length) throw new Error("Family Shield contains duplicate members.");
  if (members.filter((member) => member.role === "owner").length !== 1 || !members.some((member) => member.accountId === ownerAccountId && member.role === "owner")) {
    throw new Error("Family Shield owner membership is inconsistent.");
  }
  if (!Array.isArray(value.invitations) || value.invitations.length > MAX_FAMILY_INVITES) throw new Error("Family Shield invitation list is invalid.");
  const invitations = value.invitations.map((raw) => {
    const invite = object(raw, "Family Shield invitation");
    onlyFields(invite, ["inviteId", "secretHash", "createdByAccountId", "createdAt", "expiresAt", "usedAt"], "Family Shield invitation");
    if (!safeTimestamp(invite.createdAt) || !safeTimestamp(invite.expiresAt) || !safeTimestamp(invite.usedAt, true)) throw new Error("Family Shield invitation timestamps are invalid.");
    return {
      inviteId: id(invite.inviteId, "invite"),
      secretHash: hash(invite.secretHash, "Family invitation"),
      createdByAccountId: id(invite.createdByAccountId, "acct"),
      createdAt: Number(invite.createdAt),
      expiresAt: Number(invite.expiresAt),
      usedAt: invite.usedAt === null ? null : Number(invite.usedAt),
    };
  });
  if (!Array.isArray(value.threats) || value.threats.length > MAX_FAMILY_THREAT_CAMPAIGNS) throw new Error("Family Shield threat list is invalid.");
  const threats = value.threats.map((raw) => {
    const threat = object(raw, "Family Shield threat campaign");
    onlyFields(threat, ["campaignFingerprint", "reporterAccountIds", "familyBlockerAccountIds", "firstSeenAt", "lastSeenAt"], "Family Shield threat campaign");
    const campaignFingerprint = hash(threat.campaignFingerprint, "Family threat campaign");
    if (!Array.isArray(threat.reporterAccountIds) || !Array.isArray(threat.familyBlockerAccountIds)) throw new Error("Family Shield threat reporter lists are invalid.");
    const reporterAccountIds = threat.reporterAccountIds.map((accountId) => id(accountId, "acct"));
    const familyBlockerAccountIds = threat.familyBlockerAccountIds.map((accountId) => id(accountId, "acct"));
    if (!safeTimestamp(threat.firstSeenAt) || !safeTimestamp(threat.lastSeenAt) || Number(threat.firstSeenAt) > Number(threat.lastSeenAt)) throw new Error("Family Shield threat timestamps are invalid.");
    return {
      campaignFingerprint,
      reporterAccountIds: [...new Set(reporterAccountIds)],
      familyBlockerAccountIds: [...new Set(familyBlockerAccountIds)],
      firstSeenAt: Number(threat.firstSeenAt),
      lastSeenAt: Number(threat.lastSeenAt),
    };
  });
  if (new Set(threats.map((threat) => threat.campaignFingerprint)).size !== threats.length) throw new Error("Family Shield contains duplicate campaign records.");
  return {
    familyCircleId,
    ownerAccountId,
    createdAt: Number(value.createdAt),
    strictProtection: value.strictProtection,
    members,
    invitations,
    threats,
  };
}

function normalizeMailboxLink(input: unknown): MailboxAccountLink {
  const value = object(input, "Mailbox account link");
  onlyFields(value, ["mailboxAccountKey", "accountId", "linkedAt"], "Mailbox account link");
  if (typeof value.mailboxAccountKey !== "string" || !/^[a-f0-9]{64}$/.test(value.mailboxAccountKey)) throw new Error("Mailbox account link key is invalid.");
  if (!safeTimestamp(value.linkedAt)) throw new Error("Mailbox account link timestamp is invalid.");
  return { mailboxAccountKey: value.mailboxAccountKey, accountId: id(value.accountId, "acct"), linkedAt: Number(value.linkedAt) };
}

export function normalizeAccountPlatformState(input: unknown): AccountPlatformState {
  const value = object(input, "Account platform database");
  onlyFields(value, ["schemaVersion", "currentAccountId", "accounts", "familyCircles", "mailboxLinks"], "Account platform database");
  if (value.schemaVersion !== ACCOUNT_PLATFORM_SCHEMA_VERSION) throw new Error("Unsupported account platform database version.");
  if (!Array.isArray(value.accounts) || value.accounts.length > MAX_ACCOUNTS) throw new Error("Account platform account list is invalid.");
  if (!Array.isArray(value.familyCircles) || value.familyCircles.length > MAX_FAMILY_CIRCLES) throw new Error("Account platform family list is invalid.");
  if (!Array.isArray(value.mailboxLinks) || value.mailboxLinks.length > MAX_MAILBOX_LINKS) throw new Error("Account platform mailbox-link list is invalid.");
  const accounts = value.accounts.map(normalizeAccount);
  const familyCircles = value.familyCircles.map(normalizeFamilyCircle);
  const mailboxLinks = value.mailboxLinks.map(normalizeMailboxLink);
  if (new Set(accounts.map((account) => account.accountId)).size !== accounts.length) throw new Error("Account platform contains duplicate account IDs.");
  if (new Set(accounts.map((account) => account.username)).size !== accounts.length) throw new Error("Account platform contains duplicate usernames.");
  if (new Set(familyCircles.map((circle) => circle.familyCircleId)).size !== familyCircles.length) throw new Error("Account platform contains duplicate family IDs.");
  if (new Set(mailboxLinks.map((link) => link.mailboxAccountKey)).size !== mailboxLinks.length) throw new Error("Account platform contains duplicate mailbox links.");
  const accountIds = new Set(accounts.map((account) => account.accountId));
  for (const circle of familyCircles) {
    if (!accountIds.has(circle.ownerAccountId) || circle.members.some((member) => !accountIds.has(member.accountId))) throw new Error("Family Shield references an unknown account.");
  }
  for (const account of accounts) {
    if (account.familyCircleId && !familyCircles.some((circle) => circle.familyCircleId === account.familyCircleId && circle.members.some((member) => member.accountId === account.accountId))) {
      throw new Error("Account Family Shield membership is inconsistent.");
    }
  }
  if (mailboxLinks.some((link) => !accountIds.has(link.accountId))) throw new Error("Mailbox link references an unknown Email Shield account.");
  const currentAccountId = value.currentAccountId === null ? null : id(value.currentAccountId, "acct");
  if (currentAccountId && !accountIds.has(currentAccountId)) throw new Error("Current Email Shield account no longer exists.");
  return {
    schemaVersion: ACCOUNT_PLATFORM_SCHEMA_VERSION,
    currentAccountId,
    accounts,
    familyCircles,
    mailboxLinks,
  };
}

export class InMemoryAccountPlatformRepository implements AccountPlatformRepository {
  readonly persistent = false;
  private state: AccountPlatformState;

  constructor(initial: AccountPlatformState = emptyAccountPlatformState()) {
    this.state = normalizeAccountPlatformState(initial);
  }

  load(): AccountPlatformState {
    return cloneState(this.state);
  }

  save(state: AccountPlatformState): void {
    this.state = normalizeAccountPlatformState(state);
  }
}

export class EncryptedFileAccountPlatformRepository implements AccountPlatformRepository {
  readonly persistent = true;
  private readonly databasePath: string;
  private readonly encryptionKey: Buffer;

  constructor(readonly dataDirectory: string, encryptionKey: Buffer) {
    if (!Buffer.isBuffer(encryptionKey) || encryptionKey.length !== KEY_BYTES) throw new Error("Account platform encryption key is invalid.");
    this.databasePath = join(dataDirectory, "account-family.enc.json");
    this.encryptionKey = Buffer.from(encryptionKey);
  }

  load(): AccountPlatformState {
    if (!existsSync(this.databasePath)) return emptyAccountPlatformState();
    try {
      const raw = readBoundedRegularFile(this.databasePath, {
        description: "Encrypted account and Family Shield file",
        maxBytes: ACCOUNT_PLATFORM_ENCRYPTED_DATABASE_MAX_BYTES,
      });
      const envelope = JSON.parse(raw.toString("utf8")) as Partial<EncryptedAccountPlatformEnvelope>;
      if (Object.keys(envelope).some((field) => !["version", "algorithm", "iv", "authTag", "ciphertext"].includes(field))) throw new Error("Encrypted account platform envelope contains unknown fields.");
      if (envelope.version !== DATABASE_VERSION || envelope.algorithm !== ALGORITHM || typeof envelope.iv !== "string" || typeof envelope.authTag !== "string" || typeof envelope.ciphertext !== "string") {
        throw new Error("Unsupported encrypted account platform format.");
      }
      const decipher = createDecipheriv(ALGORITHM, this.encryptionKey, Buffer.from(envelope.iv, "base64"));
      decipher.setAAD(AAD);
      decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, "base64")),
        decipher.final(),
      ]).toString("utf8");
      if (Buffer.byteLength(plaintext, "utf8") > MAX_DATABASE_BYTES) throw new Error("Account platform database exceeds its size limit.");
      return normalizeAccountPlatformState(JSON.parse(plaintext));
    } catch (error) {
      throw new Error(`Encrypted account and Family Shield state could not be read: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  save(state: AccountPlatformState): void {
    mkdirSync(this.dataDirectory, { recursive: true, mode: 0o700 });
    try { chmodSync(this.dataDirectory, 0o700); } catch {}
    const normalized = normalizeAccountPlatformState(state);
    const plaintext = JSON.stringify(normalized);
    if (Buffer.byteLength(plaintext, "utf8") > MAX_DATABASE_BYTES) throw new Error("Account platform database exceeds its size limit.");
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGORITHM, this.encryptionKey, iv);
    cipher.setAAD(AAD);
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    const envelope: EncryptedAccountPlatformEnvelope = {
      version: DATABASE_VERSION,
      algorithm: ALGORITHM,
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
    const serialized = JSON.stringify(envelope);
    if (Buffer.byteLength(serialized, "utf8") > ACCOUNT_PLATFORM_ENCRYPTED_DATABASE_MAX_BYTES) throw new Error("Encrypted account platform file exceeds its size limit.");
    const temporaryPath = `${this.databasePath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
    writeFileSync(temporaryPath, serialized, { mode: 0o600 });
    replaceFileFromTemporaryPath(temporaryPath, this.databasePath);
    try { chmodSync(this.databasePath, 0o600); } catch {}
  }

  assertReadable(): void {
    void this.load();
  }
}

export async function createDefaultAccountPlatformRepository(
  options: AccountPlatformRepositoryFactoryOptions = {},
): Promise<AccountPlatformRepository> {
  const dataDirectory = options.dataDirectory ?? defaultEmailShieldDataDirectory();
  const databasePath = join(dataDirectory, "account-family.enc.json");
  const platform = options.platform ?? process.platform;
  const vault = options.credentialVault ?? createCredentialVault(platform);
  const databaseExists = existsSync(databasePath);

  if (!vault.capabilities().available) {
    if (databaseExists) throw new Error("Encrypted account and Family Shield state exists but its protected key is unavailable on this platform.");
    return new InMemoryAccountPlatformRepository();
  }

  const resolved = await resolveDataBoundEncryptionKey({
    vault,
    legacyReference: KEY_REFERENCE,
    dataDirectory,
    platform,
    databaseExists,
    keyBytes: KEY_BYTES,
    label: "account and Family Shield",
    validateExistingKey: (candidate) => {
      new EncryptedFileAccountPlatformRepository(dataDirectory, candidate).assertReadable();
    },
  });
  const repository = new EncryptedFileAccountPlatformRepository(dataDirectory, resolved.key);
  repository.assertReadable();
  return repository;
}
