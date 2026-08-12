import type { AccountPlatformRepository, AccountPlatformRuntime } from "./accountFamilyPorts.js";
import {
  hashRecoveryCode,
  type AccountPlatformState,
  type EmailShieldAccount,
  type FamilyCircle,
  type RegisteredDevice,
  type VerifiedEntitlement,
} from "./accountFamilyTypes.js";

export interface PrivacySafeAccountExportV1 {
  schemaVersion: 1;
  exportedAt: number;
  account: {
    accountId: string;
    username: string;
    createdAt: number;
    entitlement: VerifiedEntitlement;
    devices: Array<{
      deviceId: string;
      platform: RegisteredDevice["platform"];
      label: string;
      algorithm: RegisteredDevice["algorithm"];
      createdAt: number;
      lastSeenAt: number;
      revoked: boolean;
      current: boolean;
    }>;
    linkedMailboxCount: number;
  };
  family: null | {
    familyCircleId: string;
    role: "owner" | "member";
    createdAt: number;
    strictProtection: boolean;
    memberCount: number;
    pendingInviteCount: number;
    threatCampaignCount: number;
  };
  privacy: "no_recovery_hash_no_public_keys_no_mailbox_identity_no_mail_content";
}

export interface AccountDeletionResult {
  deletedAccountId: string;
  removedMailboxLinks: number;
  removedPendingFamilyEvidence: number;
}

export interface FamilyDeletionResult {
  deletedFamilyCircleId: string;
  releasedMembers: number;
  removedInvitations: number;
  removedThreatCampaigns: number;
}

function cloneState(state: AccountPlatformState): AccountPlatformState {
  return structuredClone(state);
}

function activeDevice(account: EmailShieldAccount, deviceId: string): RegisteredDevice | null {
  return account.devices.find((device) => device.deviceId === deviceId && device.revokedAt === null) ?? null;
}

/**
 * Security-sensitive account/family lifecycle operations shared by desktop and
 * the remote account service. It never receives mailbox bodies, provider
 * credentials or local scan history, so account deletion cannot accidentally
 * become a mailbox-data deletion/upload path.
 */
export class AccountLifecycleService {
  constructor(
    private readonly repository: AccountPlatformRepository,
    private readonly runtime: AccountPlatformRuntime,
  ) {}

  private read(): AccountPlatformState {
    return cloneState(this.repository.load());
  }

  private write(state: AccountPlatformState): void {
    this.repository.save(cloneState(state));
  }

  private current(state: AccountPlatformState): EmailShieldAccount {
    const account = state.accounts.find((candidate) => candidate.accountId === state.currentAccountId);
    if (!account) throw new Error("Sign in to an Email Shield account first.");
    return account;
  }

  private requireCurrentDevice(account: EmailShieldAccount, currentDeviceId: string): RegisteredDevice {
    const device = activeDevice(account, currentDeviceId);
    if (!device) throw new Error("The current trusted device is no longer registered to this Email Shield account.");
    return device;
  }

  private circleForAccount(state: AccountPlatformState, account: EmailShieldAccount): FamilyCircle | null {
    if (!account.familyCircleId) return null;
    return state.familyCircles.find((circle) => circle.familyCircleId === account.familyCircleId) ?? null;
  }

  rotateRecoveryCode(currentDeviceId: string): { recoveryCode: string } {
    const state = this.read();
    const account = this.current(state);
    this.requireCurrentDevice(account, currentDeviceId);
    const recoveryCode = this.runtime.secret(24);
    if (recoveryCode.length < 24) throw new Error("Account runtime returned an invalid recovery secret.");
    account.recoveryCodeHash = hashRecoveryCode(recoveryCode);
    this.write(state);
    return { recoveryCode };
  }

  revokeOtherDevices(currentDeviceId: string): { revoked: number } {
    const state = this.read();
    const account = this.current(state);
    this.requireCurrentDevice(account, currentDeviceId);
    const now = this.runtime.now();
    let revoked = 0;
    for (const device of account.devices) {
      if (device.deviceId === currentDeviceId || device.revokedAt !== null) continue;
      device.revokedAt = now;
      revoked += 1;
    }
    this.write(state);
    return { revoked };
  }

  signOutEverywhere(currentDeviceId: string): { revoked: number } {
    const state = this.read();
    const account = this.current(state);
    this.requireCurrentDevice(account, currentDeviceId);
    const now = this.runtime.now();
    let revoked = 0;
    for (const device of account.devices) {
      if (device.revokedAt !== null) continue;
      device.revokedAt = now;
      revoked += 1;
    }
    state.currentAccountId = null;
    this.write(state);
    return { revoked };
  }

  deleteFamilyCircle(currentDeviceId: string): FamilyDeletionResult {
    const state = this.read();
    const account = this.current(state);
    this.requireCurrentDevice(account, currentDeviceId);
    const circle = this.circleForAccount(state, account);
    if (!circle || circle.ownerAccountId !== account.accountId) {
      throw new Error("Only the Family Shield owner can delete this circle.");
    }

    const releasedMembers = circle.members.length;
    const removedInvitations = circle.invitations.length;
    const removedThreatCampaigns = circle.threats.length;
    for (const member of circle.members) {
      const memberAccount = state.accounts.find((candidate) => candidate.accountId === member.accountId);
      if (memberAccount?.familyCircleId === circle.familyCircleId) memberAccount.familyCircleId = null;
    }
    state.familyCircles = state.familyCircles.filter((candidate) => candidate.familyCircleId !== circle.familyCircleId);
    this.write(state);
    return {
      deletedFamilyCircleId: circle.familyCircleId,
      releasedMembers,
      removedInvitations,
      removedThreatCampaigns,
    };
  }

  exportAccountMetadata(currentDeviceId: string): PrivacySafeAccountExportV1 {
    const state = this.read();
    const account = this.current(state);
    this.requireCurrentDevice(account, currentDeviceId);
    const circle = this.circleForAccount(state, account);
    const now = this.runtime.now();
    const family = circle
      ? {
          familyCircleId: circle.familyCircleId,
          role: (circle.ownerAccountId === account.accountId ? "owner" : "member") as "owner" | "member",
          createdAt: circle.createdAt,
          strictProtection: circle.strictProtection,
          memberCount: circle.members.length,
          pendingInviteCount: circle.invitations.filter((invite) => invite.usedAt === null && invite.expiresAt > now).length,
          threatCampaignCount: circle.threats.length,
        }
      : null;

    return {
      schemaVersion: 1,
      exportedAt: now,
      account: {
        accountId: account.accountId,
        username: account.username,
        createdAt: account.createdAt,
        entitlement: structuredClone(account.entitlement),
        devices: account.devices.map((device) => ({
          deviceId: device.deviceId,
          platform: device.platform,
          label: device.label,
          algorithm: device.algorithm,
          createdAt: device.createdAt,
          lastSeenAt: device.lastSeenAt,
          revoked: device.revokedAt !== null,
          current: device.deviceId === currentDeviceId,
        })),
        linkedMailboxCount: state.mailboxLinks.filter((link) => link.accountId === account.accountId).length,
      },
      family,
      privacy: "no_recovery_hash_no_public_keys_no_mailbox_identity_no_mail_content",
    };
  }

  deleteAccount(currentDeviceId: string): AccountDeletionResult {
    const state = this.read();
    const account = this.current(state);
    this.requireCurrentDevice(account, currentDeviceId);
    const circle = this.circleForAccount(state, account);
    if (circle?.ownerAccountId === account.accountId) {
      throw new Error("Delete or transfer the Family Shield circle before deleting its owner account.");
    }

    let removedPendingFamilyEvidence = 0;
    if (circle) {
      circle.members = circle.members.filter((member) => member.accountId !== account.accountId);
      for (const threat of circle.threats) {
        const before = threat.reporterAccountIds.length + threat.familyBlockerAccountIds.length;
        threat.reporterAccountIds = threat.reporterAccountIds.filter((id) => id !== account.accountId);
        threat.familyBlockerAccountIds = threat.familyBlockerAccountIds.filter((id) => id !== account.accountId);
        removedPendingFamilyEvidence += before - threat.reporterAccountIds.length - threat.familyBlockerAccountIds.length;
      }
    }

    const linkedBefore = state.mailboxLinks.length;
    state.mailboxLinks = state.mailboxLinks.filter((link) => link.accountId !== account.accountId);
    state.accounts = state.accounts.filter((candidate) => candidate.accountId !== account.accountId);
    state.currentAccountId = null;
    this.write(state);
    return {
      deletedAccountId: account.accountId,
      removedMailboxLinks: linkedBefore - state.mailboxLinks.length,
      removedPendingFamilyEvidence,
    };
  }
}
