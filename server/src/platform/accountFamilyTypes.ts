import { sha256Hex } from "../core/sha256.js";

export const ACCOUNT_PLATFORM_SCHEMA_VERSION = 1 as const;
export const FAMILY_DEFAULT_SEAT_LIMIT = 6;
export const MAX_ACCOUNT_DEVICES = 12;
export const MAX_FAMILY_MEMBERS = 12;
export const MAX_FAMILY_INVITES = 24;
export const MAX_FAMILY_THREAT_CAMPAIGNS = 5_000;
export const FAMILY_INVITE_TTL_MS = 24 * 60 * 60 * 1_000;

export type EmailShieldPlan = "free" | "individual" | "family";
export type EntitlementStatus = "active" | "grace" | "expired" | "revoked";
export type EntitlementSource = "development" | "apple" | "google" | "web";
export type DevicePlatform = "desktop" | "ios" | "android";
export type DeviceKeyAlgorithm = "p256" | "ed25519";
export type FamilyMemberRole = "owner" | "member";
export type FamilyThreatSource = "report_scam" | "family_block";
export type FamilyThreatStatus = "candidate" | "warning" | "confirmed";
export type FamilyProtectionDisposition = "none" | "quarantine" | "trash";

export interface DevicePublicIdentity {
  algorithm: DeviceKeyAlgorithm;
  publicKeySpki: string;
  platform: DevicePlatform;
  label: string;
}

export interface RegisteredDevice extends DevicePublicIdentity {
  deviceId: string;
  createdAt: number;
  lastSeenAt: number;
  revokedAt: number | null;
}

export interface VerifiedEntitlement {
  plan: EmailShieldPlan;
  status: EntitlementStatus;
  source: EntitlementSource;
  productId: string;
  storeAccountReference: string | null;
  verifiedAt: number;
  expiresAt: number | null;
  graceUntil: number | null;
  seatLimit: number;
}

export interface EmailShieldAccount {
  accountId: string;
  username: string;
  createdAt: number;
  recoveryCodeHash: string;
  devices: RegisteredDevice[];
  entitlement: VerifiedEntitlement;
  familyCircleId: string | null;
}

export interface FamilyMember {
  accountId: string;
  role: FamilyMemberRole;
  joinedAt: number;
}

export interface FamilyInvitation {
  inviteId: string;
  secretHash: string;
  createdByAccountId: string;
  createdAt: number;
  expiresAt: number;
  usedAt: number | null;
}

export interface FamilyThreatCampaign {
  campaignFingerprint: string;
  reporterAccountIds: string[];
  familyBlockerAccountIds: string[];
  firstSeenAt: number;
  lastSeenAt: number;
}

export interface FamilyCircle {
  familyCircleId: string;
  ownerAccountId: string;
  createdAt: number;
  strictProtection: boolean;
  members: FamilyMember[];
  invitations: FamilyInvitation[];
  threats: FamilyThreatCampaign[];
}

export interface MailboxAccountLink {
  mailboxAccountKey: string;
  accountId: string;
  linkedAt: number;
}

export interface AccountPlatformState {
  schemaVersion: typeof ACCOUNT_PLATFORM_SCHEMA_VERSION;
  currentAccountId: string | null;
  accounts: EmailShieldAccount[];
  familyCircles: FamilyCircle[];
  mailboxLinks: MailboxAccountLink[];
}

export interface FamilyThreatSnapshotEntry {
  campaignFingerprint: string;
  status: FamilyThreatStatus;
}

export interface FamilyThreatSnapshot {
  familyCircleId: string;
  accountId: string;
  entries: FamilyThreatSnapshotEntry[];
}

export interface PublicDeviceSnapshot {
  deviceId: string;
  platform: DevicePlatform;
  label: string;
  algorithm: DeviceKeyAlgorithm;
  createdAt: number;
  lastSeenAt: number;
  revoked: boolean;
}

export interface PublicFamilyMemberSnapshot {
  accountId: string;
  username: string;
  role: FamilyMemberRole;
  joinedAt: number;
  activeDevices: number;
}

export interface PublicAccountPlatformSnapshot {
  signedIn: boolean;
  deviceId: string;
  account: null | {
    accountId: string;
    username: string;
    devices: PublicDeviceSnapshot[];
    entitlement: VerifiedEntitlement;
  };
  family: null | {
    familyCircleId: string;
    strictProtection: boolean;
    seatLimit: number;
    seatsUsed: number;
    members: PublicFamilyMemberSnapshot[];
    pendingInvites: number;
    threatCampaigns: number;
    warningCampaigns: number;
    confirmedCampaigns: number;
  };
}

export function emptyAccountPlatformState(): AccountPlatformState {
  return {
    schemaVersion: ACCOUNT_PLATFORM_SCHEMA_VERSION,
    currentAccountId: null,
    accounts: [],
    familyCircles: [],
    mailboxLinks: [],
  };
}

export function normalizeUsername(value: unknown): string {
  if (typeof value !== "string") throw new Error("Username is required.");
  const username = value.trim().toLowerCase();
  if (username.length < 3 || username.length > 32) {
    throw new Error("Username must contain between 3 and 32 characters.");
  }
  if (!/^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/.test(username)) {
    throw new Error("Username may contain lowercase letters, numbers, dots, underscores and hyphens.");
  }
  if (/^(?:admin|administrator|support|emailshield|email-shield|system|root)$/.test(username)) {
    throw new Error("That username is reserved.");
  }
  return username;
}

export function normalizeDeviceLabel(value: unknown): string {
  if (typeof value !== "string") throw new Error("Device label is required.");
  const label = value.trim().replace(/\s+/g, " ");
  if (label.length < 1 || label.length > 64) throw new Error("Device label must contain 1 to 64 characters.");
  if(/[\u0000-\u001f\u007f]/.test(label)) throw new Error("Device label contains control characters.");
  return label;
}

export function normalizePublicKeySpki(value: unknown): string {
  if (typeof value !== "string") throw new Error("Device public key is required.");
  const normalized = value.trim();
  if (normalized.length < 32 || normalized.length > 4096 || !/^[A-Za-z0-9+/=]+$/.test(normalized)) {
    throw new Error("Device public key is invalid.");
  }
  return normalized;
}

export function deriveDeviceId(identity: Pick<DevicePublicIdentity, "algorithm" | "publicKeySpki">): string {
  const publicKey = normalizePublicKeySpki(identity.publicKeySpki);
  if (!["p256", "ed25519"].includes(identity.algorithm)) throw new Error("Device key algorithm is invalid.");
  return `dev_${sha256Hex(`email-shield-device-v1\n${identity.algorithm}\n${publicKey}`)}`;
}

export function hashRecoveryCode(secret: string): string {
  return sha256Hex(`email-shield-recovery-v1\n${secret.trim()}`);
}

export function hashFamilyInviteSecret(secret: string): string {
  return sha256Hex(`email-shield-family-invite-v1\n${secret.trim()}`);
}

export function defaultFreeEntitlement(now: number): VerifiedEntitlement {
  return {
    plan: "free",
    status: "active",
    source: "development",
    productId: "email-shield-free",
    storeAccountReference: null,
    verifiedAt: now,
    expiresAt: null,
    graceUntil: null,
    seatLimit: 1,
  };
}

export function entitlementActive(entitlement: VerifiedEntitlement, now: number): boolean {
  if (entitlement.status === "revoked" || entitlement.status === "expired") return false;
  if (entitlement.expiresAt === null || entitlement.expiresAt > now) return true;
  return entitlement.status === "grace" && entitlement.graceUntil !== null && entitlement.graceUntil > now;
}

export function familySeatLimit(entitlement: VerifiedEntitlement, now: number): number {
  if (!entitlementActive(entitlement, now) || entitlement.plan !== "family") return 0;
  return Math.max(1, Math.min(MAX_FAMILY_MEMBERS, entitlement.seatLimit));
}

export function familyThreatStatus(circle: FamilyCircle, threat: FamilyThreatCampaign): FamilyThreatStatus {
  const members = new Set(circle.members.map((member) => member.accountId));
  const reporters = [...new Set(threat.reporterAccountIds)].filter((accountId) => members.has(accountId));
  const blockers = [...new Set(threat.familyBlockerAccountIds)].filter((accountId) => members.has(accountId));
  const ownerBlocked = blockers.includes(circle.ownerAccountId);
  if (ownerBlocked || (circle.strictProtection && reporters.length >= 1) || reporters.length >= 2 || blockers.length >= 2) {
    return "confirmed";
  }
  if (reporters.length >= 1 || blockers.length >= 1) return "warning";
  return "candidate";
}

export function resolveFamilyProtection(
  campaignFingerprint: string,
  snapshot: FamilyThreatSnapshot | null | undefined,
): FamilyProtectionDisposition {
  if (!snapshot || !/^[a-f0-9]{64}$/.test(campaignFingerprint)) return "none";
  const entry = snapshot.entries.find((item) => item.campaignFingerprint === campaignFingerprint);
  if (!entry || entry.status === "candidate") return "none";
  return entry.status === "confirmed" ? "trash" : "quarantine";
}
