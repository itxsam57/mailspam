import type {
  AccountPlatformState,
  DevicePublicIdentity,
  EmailShieldPlan,
  FamilyThreatSnapshot,
  PublicAccountPlatformSnapshot,
  VerifiedEntitlement,
} from "./accountFamilyTypes.js";

/**
 * Storage boundary for the portable account/family domain. Desktop uses an
 * encrypted local repository for acceptance. A production account service can
 * implement the same logical contract remotely without changing domain rules.
 */
export interface AccountPlatformRepository {
  readonly persistent: boolean;
  load(): AccountPlatformState;
  save(state: AccountPlatformState): void;
}

/** Entropy/time are injected so account rules remain deterministic in tests. */
export interface AccountPlatformRuntime {
  now(): number;
  id(prefix: "acct" | "family" | "invite"): string;
  secret(bytes?: number): string;
}

/**
 * Shell-owned device identity. Private keys never enter AccountPlatformState.
 * Desktop stores its private key in the native credential vault. Android/iOS
 * implementations must use Keystore/Keychain/Secure Enclave where available.
 */
export interface DeviceIdentityPort {
  currentPublicIdentity(): Promise<DevicePublicIdentity>;
  signChallenge(challenge: string): Promise<string>;
}

/**
 * Store purchase verification is authoritative. UI clients may request a
 * product, but they never set plan/status directly. Apple/Google/web adapters
 * return a normalized verified entitlement only after receipt verification.
 */
export interface PurchaseVerificationPort {
  verifyPurchase(input: {
    accountId: string;
    plan: Exclude<EmailShieldPlan, "free">;
    productId: string;
    purchaseProof: string;
    storeAccountReference: string | null;
  }): Promise<VerifiedEntitlement>;
}

/**
 * Cross-device sync boundary. Family payloads contain account/circle metadata
 * and privacy-reduced campaign fingerprints only; never mailbox content.
 */
export interface FamilySyncPort {
  refresh(accountId: string): Promise<void>;
  publishThreat(input: {
    accountId: string;
    familyCircleId: string;
    campaignFingerprint: string;
    source: "report_scam" | "family_block";
  }): Promise<void>;
}

/** Native notification bridge for future phone shells. */
export interface NotificationPort {
  protectionApplied(input: {
    kind: "family_warning" | "family_confirmed" | "community_warning" | "community_confirmed";
    count: number;
  }): Promise<void>;
}

/**
 * This is the app-facing contract Android/iOS/desktop consume. A native app is
 * therefore a shell/adapter around one shared domain, not a fork of product
 * behavior.
 */
export interface AccountPlatformClient {
  snapshot(): Promise<PublicAccountPlatformSnapshot>;
  createAccount(username: string, deviceLabel: string): Promise<{ recoveryCode: string; snapshot: PublicAccountPlatformSnapshot }>;
  signIn(username: string): Promise<PublicAccountPlatformSnapshot>;
  signOut(): Promise<void>;
  createFamily(): Promise<PublicAccountPlatformSnapshot>;
  createFamilyInvite(): Promise<{ inviteCode: string; expiresAt: number }>;
  joinFamily(inviteCode: string): Promise<PublicAccountPlatformSnapshot>;
  leaveFamily(): Promise<PublicAccountPlatformSnapshot>;
  setStrictFamilyProtection(enabled: boolean): Promise<PublicAccountPlatformSnapshot>;
  familyThreatSnapshot(mailboxAccountKey: string): Promise<FamilyThreatSnapshot | null>;
}
