import type { AccountPlatformRepository, AccountPlatformRuntime } from "./accountFamilyPorts.js";
import {
  FAMILY_INVITE_TTL_MS,
  MAX_ACCOUNT_DEVICES,
  MAX_FAMILY_INVITES,
  MAX_FAMILY_THREAT_CAMPAIGNS,
  defaultFreeEntitlement,
  deriveDeviceId,
  entitlementActive,
  familySeatLimit,
  familyThreatStatus,
  hashFamilyInviteSecret,
  hashRecoveryCode,
  normalizeDeviceLabel,
  normalizePublicKeySpki,
  normalizeUsername,
  type AccountPlatformState,
  type DevicePublicIdentity,
  type EmailShieldAccount,
  type FamilyCircle,
  type FamilyThreatSnapshot,
  type FamilyThreatSource,
  type PublicAccountPlatformSnapshot,
  type RegisteredDevice,
  type VerifiedEntitlement,
} from "./accountFamilyTypes.js";

const MAX_ACCOUNTS = 128;
const MAX_MAILBOX_LINKS = 256;

function cloneState(state: AccountPlatformState): AccountPlatformState {
  return structuredClone(state);
}

function unique<T>(values: Iterable<T>): T[] {
  return [...new Set(values)];
}

function assertFingerprint(value: string): void {
  if (!/^[a-f0-9]{64}$/.test(value)) throw new Error("Family campaign fingerprint is invalid.");
}

function assertEntitlement(value: VerifiedEntitlement): void {
  if (!["free", "individual", "family"].includes(value.plan)) throw new Error("Entitlement plan is invalid.");
  if (!["active", "grace", "expired", "revoked"].includes(value.status)) throw new Error("Entitlement status is invalid.");
  if (!["development", "apple", "google", "web"].includes(value.source)) throw new Error("Entitlement source is invalid.");
  if (typeof value.productId !== "string" || value.productId.length < 1 || value.productId.length > 128) {
    throw new Error("Entitlement product ID is invalid.");
  }
  if (value.storeAccountReference !== null && (
    typeof value.storeAccountReference !== "string" ||
    value.storeAccountReference.length < 8 ||
    value.storeAccountReference.length > 256
  )) throw new Error("Entitlement store account reference is invalid.");
  if (!Number.isSafeInteger(value.verifiedAt) || value.verifiedAt <= 0) throw new Error("Entitlement verification time is invalid.");
  if (value.expiresAt !== null && (!Number.isSafeInteger(value.expiresAt) || value.expiresAt <= 0)) {
    throw new Error("Entitlement expiry is invalid.");
  }
  if (value.graceUntil !== null && (!Number.isSafeInteger(value.graceUntil) || value.graceUntil <= 0)) {
    throw new Error("Entitlement grace expiry is invalid.");
  }
  if (!Number.isSafeInteger(value.seatLimit) || value.seatLimit < 1 || value.seatLimit > 12) {
    throw new Error("Entitlement seat limit is invalid.");
  }
  if (value.plan !== "family" && value.seatLimit !== 1) throw new Error("Non-family plans may contain exactly one seat.");
  if (value.plan === "family" && value.seatLimit < 2) throw new Error("Family plans require at least two seats.");
}

function normalizeDevice(identity: DevicePublicIdentity, now: number): RegisteredDevice {
  if (!["desktop", "ios", "android"].includes(identity.platform)) throw new Error("Device platform is invalid.");
  if (!["p256", "ed25519"].includes(identity.algorithm)) throw new Error("Device key algorithm is invalid.");
  const publicKeySpki = normalizePublicKeySpki(identity.publicKeySpki);
  const label = normalizeDeviceLabel(identity.label);
  const deviceId = deriveDeviceId({ algorithm: identity.algorithm, publicKeySpki });
  return {
    deviceId,
    algorithm: identity.algorithm,
    publicKeySpki,
    platform: identity.platform,
    label,
    createdAt: now,
    lastSeenAt: now,
    revokedAt: null,
  };
}

export class AccountPlatformService {
  constructor(
    private readonly repository: AccountPlatformRepository,
    private readonly runtime: AccountPlatformRuntime,
  ) {}

  persistent(): boolean {
    return this.repository.persistent;
  }

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

  private circleForAccount(state: AccountPlatformState, account: EmailShieldAccount): FamilyCircle | null {
    if (!account.familyCircleId) return null;
    return state.familyCircles.find((circle) => circle.familyCircleId === account.familyCircleId) ?? null;
  }

  private ownerForCircle(state: AccountPlatformState, circle: FamilyCircle): EmailShieldAccount {
    const owner = state.accounts.find((account) => account.accountId === circle.ownerAccountId);
    if (!owner) throw new Error("Family Shield owner account is missing.");
    return owner;
  }

  private requireActiveFamily(state: AccountPlatformState, circle: FamilyCircle): { owner: EmailShieldAccount; seatLimit: number } {
    const owner = this.ownerForCircle(state, circle);
    const seatLimit = familySeatLimit(owner.entitlement, this.runtime.now());
    if (seatLimit < 2) throw new Error("Family Shield is paused because the owner does not have an active Family entitlement.");
    return { owner, seatLimit };
  }

  private publicSnapshot(state: AccountPlatformState, deviceId: string): PublicAccountPlatformSnapshot {
    const account = state.accounts.find((candidate) => candidate.accountId === state.currentAccountId) ?? null;
    if (!account) return { signedIn: false, deviceId, account: null, family: null };

    const circle = this.circleForAccount(state, account);
    let family: PublicAccountPlatformSnapshot["family"] = null;
    if (circle) {
      const owner = this.ownerForCircle(state, circle);
      const seatLimit = familySeatLimit(owner.entitlement, this.runtime.now());
      const statuses = circle.threats.map((threat) => familyThreatStatus(circle, threat));
      family = {
        familyCircleId: circle.familyCircleId,
        strictProtection: circle.strictProtection,
        seatLimit,
        seatsUsed: circle.members.length,
        members: circle.members.map((member) => {
          const memberAccount = state.accounts.find((candidate) => candidate.accountId === member.accountId);
          return {
            accountId: member.accountId,
            username: memberAccount?.username ?? "unknown-member",
            role: member.role,
            joinedAt: member.joinedAt,
            activeDevices: memberAccount?.devices.filter((device) => device.revokedAt === null).length ?? 0,
          };
        }),
        pendingInvites: circle.invitations.filter((invite) => invite.usedAt === null && invite.expiresAt > this.runtime.now()).length,
        threatCampaigns: circle.threats.length,
        warningCampaigns: statuses.filter((status) => status === "warning").length,
        confirmedCampaigns: statuses.filter((status) => status === "confirmed").length,
      };
    }

    return {
      signedIn: true,
      deviceId,
      account: {
        accountId: account.accountId,
        username: account.username,
        devices: account.devices.map((device) => ({
          deviceId: device.deviceId,
          platform: device.platform,
          label: device.label,
          algorithm: device.algorithm,
          createdAt: device.createdAt,
          lastSeenAt: device.lastSeenAt,
          revoked: device.revokedAt !== null,
        })),
        entitlement: structuredClone(account.entitlement),
      },
      family,
    };
  }

  snapshot(deviceId: string): PublicAccountPlatformSnapshot {
    return this.publicSnapshot(this.read(), deviceId);
  }

  createAccount(usernameInput: unknown, identity: DevicePublicIdentity): {
    recoveryCode: string;
    snapshot: PublicAccountPlatformSnapshot;
  } {
    const state = this.read();
    if (state.accounts.length >= MAX_ACCOUNTS) throw new Error("Local Email Shield account capacity has been reached.");
    const username = normalizeUsername(usernameInput);
    if (state.accounts.some((account) => account.username === username)) throw new Error("That Email Shield username already exists.");
    const now = this.runtime.now();
    const device = normalizeDevice(identity, now);
    const recoveryCode = this.runtime.secret(24);
    if (recoveryCode.length < 24) throw new Error("Account runtime returned an invalid recovery secret.");
    const account: EmailShieldAccount = {
      accountId: this.runtime.id("acct"),
      username,
      createdAt: now,
      recoveryCodeHash: hashRecoveryCode(recoveryCode),
      devices: [device],
      entitlement: defaultFreeEntitlement(now),
      familyCircleId: null,
    };
    state.accounts.push(account);
    state.currentAccountId = account.accountId;
    this.write(state);
    return { recoveryCode, snapshot: this.publicSnapshot(state, device.deviceId) };
  }

  signIn(usernameInput: unknown, deviceId: string): PublicAccountPlatformSnapshot {
    const state = this.read();
    const username = normalizeUsername(usernameInput);
    const account = state.accounts.find((candidate) => candidate.username === username);
    if (!account) throw new Error("Unknown Email Shield username.");
    const device = account.devices.find((candidate) => candidate.deviceId === deviceId && candidate.revokedAt === null);
    if (!device) throw new Error("This device is not registered to that Email Shield account. Use a trusted-device pairing or recovery flow.");
    device.lastSeenAt = this.runtime.now();
    state.currentAccountId = account.accountId;
    this.write(state);
    return this.publicSnapshot(state, deviceId);
  }

  recoverAccount(usernameInput: unknown, recoveryCode: string, identity: DevicePublicIdentity): {
    recoveryCode: string;
    snapshot: PublicAccountPlatformSnapshot;
  } {
    const state = this.read();
    const username = normalizeUsername(usernameInput);
    const account = state.accounts.find((candidate) => candidate.username === username);
    if (!account || hashRecoveryCode(recoveryCode) !== account.recoveryCodeHash) {
      throw new Error("The Email Shield recovery code is invalid.");
    }
    const now = this.runtime.now();
    const device = normalizeDevice(identity, now);
    const existing = account.devices.find((candidate) => candidate.deviceId === device.deviceId);
    if (existing) {
      existing.revokedAt = null;
      existing.lastSeenAt = now;
      existing.label = device.label;
    } else {
      if (account.devices.length >= MAX_ACCOUNT_DEVICES) throw new Error("Account device capacity has been reached.");
      account.devices.push(device);
    }
    const nextRecoveryCode = this.runtime.secret(24);
    account.recoveryCodeHash = hashRecoveryCode(nextRecoveryCode);
    state.currentAccountId = account.accountId;
    this.write(state);
    return { recoveryCode: nextRecoveryCode, snapshot: this.publicSnapshot(state, device.deviceId) };
  }

  signOut(): void {
    const state = this.read();
    state.currentAccountId = null;
    this.write(state);
  }

  registerDevice(identity: DevicePublicIdentity, currentDeviceId: string): PublicAccountPlatformSnapshot {
    const state = this.read();
    const account = this.current(state);
    if (!account.devices.some((device) => device.deviceId === currentDeviceId && device.revokedAt === null)) {
      throw new Error("The current trusted device is no longer registered.");
    }
    const device = normalizeDevice(identity, this.runtime.now());
    const existing = account.devices.find((candidate) => candidate.deviceId === device.deviceId);
    if (existing) {
      existing.revokedAt = null;
      existing.lastSeenAt = this.runtime.now();
      existing.label = device.label;
    } else {
      if (account.devices.length >= MAX_ACCOUNT_DEVICES) throw new Error("Account device capacity has been reached.");
      account.devices.push(device);
    }
    this.write(state);
    return this.publicSnapshot(state, currentDeviceId);
  }

  revokeDevice(deviceId: string, currentDeviceId: string): PublicAccountPlatformSnapshot {
    const state = this.read();
    const account = this.current(state);
    const device = account.devices.find((candidate) => candidate.deviceId === deviceId);
    if (!device) throw new Error("Unknown account device.");
    const remaining = account.devices.filter((candidate) => candidate.deviceId !== deviceId && candidate.revokedAt === null);
    if (remaining.length === 0) throw new Error("At least one trusted device must remain registered. Use account recovery before revoking the final device.");
    device.revokedAt = this.runtime.now();
    if (deviceId === currentDeviceId) state.currentAccountId = null;
    this.write(state);
    return this.publicSnapshot(state, currentDeviceId);
  }

  applyVerifiedEntitlement(entitlement: VerifiedEntitlement, currentDeviceId: string): PublicAccountPlatformSnapshot {
    assertEntitlement(entitlement);
    const state = this.read();
    const account = this.current(state);
    account.entitlement = structuredClone(entitlement);
    this.write(state);
    return this.publicSnapshot(state, currentDeviceId);
  }

  createFamily(currentDeviceId: string): PublicAccountPlatformSnapshot {
    const state = this.read();
    const account = this.current(state);
    if (account.familyCircleId) throw new Error("This account already belongs to a Family Shield circle.");
    const seatLimit = familySeatLimit(account.entitlement, this.runtime.now());
    if (seatLimit < 2) throw new Error("An active Email Shield Family entitlement is required to create Family Shield.");
    const now = this.runtime.now();
    const circle: FamilyCircle = {
      familyCircleId: this.runtime.id("family"),
      ownerAccountId: account.accountId,
      createdAt: now,
      strictProtection: false,
      members: [{ accountId: account.accountId, role: "owner", joinedAt: now }],
      invitations: [],
      threats: [],
    };
    state.familyCircles.push(circle);
    account.familyCircleId = circle.familyCircleId;
    this.write(state);
    return this.publicSnapshot(state, currentDeviceId);
  }

  createFamilyInvite(): { inviteCode: string; expiresAt: number } {
    const state = this.read();
    const account = this.current(state);
    const circle = this.circleForAccount(state, account);
    if (!circle || circle.ownerAccountId !== account.accountId) throw new Error("Only the Family Shield owner can invite members.");
    const { seatLimit } = this.requireActiveFamily(state, circle);
    if (circle.members.length >= seatLimit) throw new Error("All Family Shield seats are currently in use.");
    const now = this.runtime.now();
    circle.invitations = circle.invitations.filter((invite) => invite.usedAt === null && invite.expiresAt > now);
    if (circle.invitations.length >= MAX_FAMILY_INVITES) throw new Error("Too many pending Family Shield invitations exist.");
    const inviteCode = this.runtime.secret(24);
    const expiresAt = now + FAMILY_INVITE_TTL_MS;
    circle.invitations.push({
      inviteId: this.runtime.id("invite"),
      secretHash: hashFamilyInviteSecret(inviteCode),
      createdByAccountId: account.accountId,
      createdAt: now,
      expiresAt,
      usedAt: null,
    });
    this.write(state);
    return { inviteCode, expiresAt };
  }

  joinFamily(inviteCode: string, currentDeviceId: string): PublicAccountPlatformSnapshot {
    const state = this.read();
    const account = this.current(state);
    if (account.familyCircleId) throw new Error("This account already belongs to a Family Shield circle.");
    const secretHash = hashFamilyInviteSecret(inviteCode);
    const now = this.runtime.now();
    const circle = state.familyCircles.find((candidate) => candidate.invitations.some(
      (invite) => invite.secretHash === secretHash && invite.usedAt === null && invite.expiresAt > now,
    ));
    if (!circle) throw new Error("The Family Shield invitation is invalid, expired or already used.");
    const { seatLimit } = this.requireActiveFamily(state, circle);
    if (circle.members.length >= seatLimit) throw new Error("The Family Shield subscription has no available seats.");
    const invite = circle.invitations.find((candidate) => candidate.secretHash === secretHash && candidate.usedAt === null)!;
    invite.usedAt = now;
    circle.members.push({ accountId: account.accountId, role: "member", joinedAt: now });
    account.familyCircleId = circle.familyCircleId;
    this.write(state);
    return this.publicSnapshot(state, currentDeviceId);
  }

  removeFamilyMember(memberAccountId: string, currentDeviceId: string): PublicAccountPlatformSnapshot {
    const state = this.read();
    const account = this.current(state);
    const circle = this.circleForAccount(state, account);
    if (!circle || circle.ownerAccountId !== account.accountId) throw new Error("Only the Family Shield owner can remove members.");
    if (memberAccountId === circle.ownerAccountId) throw new Error("The Family Shield owner cannot be removed from the circle.");
    const member = circle.members.find((candidate) => candidate.accountId === memberAccountId);
    if (!member) throw new Error("That account is not a member of this Family Shield circle.");
    circle.members = circle.members.filter((candidate) => candidate.accountId !== memberAccountId);
    for (const threat of circle.threats) {
      threat.reporterAccountIds = threat.reporterAccountIds.filter((id) => id !== memberAccountId);
      threat.familyBlockerAccountIds = threat.familyBlockerAccountIds.filter((id) => id !== memberAccountId);
    }
    const memberAccount = state.accounts.find((candidate) => candidate.accountId === memberAccountId);
    if (memberAccount) memberAccount.familyCircleId = null;
    this.write(state);
    return this.publicSnapshot(state, currentDeviceId);
  }

  leaveFamily(currentDeviceId: string): PublicAccountPlatformSnapshot {
    const state = this.read();
    const account = this.current(state);
    const circle = this.circleForAccount(state, account);
    if (!circle) throw new Error("This account is not in a Family Shield circle.");
    if (circle.ownerAccountId === account.accountId) throw new Error("The Family Shield owner must remove other members before closing or transferring the circle.");
    circle.members = circle.members.filter((member) => member.accountId !== account.accountId);
    for (const threat of circle.threats) {
      threat.reporterAccountIds = threat.reporterAccountIds.filter((id) => id !== account.accountId);
      threat.familyBlockerAccountIds = threat.familyBlockerAccountIds.filter((id) => id !== account.accountId);
    }
    account.familyCircleId = null;
    this.write(state);
    return this.publicSnapshot(state, currentDeviceId);
  }

  setStrictFamilyProtection(enabled: boolean, currentDeviceId: string): PublicAccountPlatformSnapshot {
    const state = this.read();
    const account = this.current(state);
    const circle = this.circleForAccount(state, account);
    if (!circle || circle.ownerAccountId !== account.accountId) throw new Error("Only the Family Shield owner can change strict protection.");
    this.requireActiveFamily(state, circle);
    circle.strictProtection = enabled;
    this.write(state);
    return this.publicSnapshot(state, currentDeviceId);
  }

  linkMailbox(mailboxAccountKey: string): void {
    if (!/^[a-f0-9]{64}$/.test(mailboxAccountKey)) throw new Error("Mailbox account key is invalid.");
    const state = this.read();
    const account = this.current(state);
    const existing = state.mailboxLinks.find((link) => link.mailboxAccountKey === mailboxAccountKey);
    if (existing) {
      existing.accountId = account.accountId;
      existing.linkedAt = this.runtime.now();
    } else {
      if (state.mailboxLinks.length >= MAX_MAILBOX_LINKS) throw new Error("Mailbox profile-link capacity has been reached.");
      state.mailboxLinks.push({ mailboxAccountKey, accountId: account.accountId, linkedAt: this.runtime.now() });
    }
    this.write(state);
  }

  accountForMailbox(mailboxAccountKey: string): EmailShieldAccount | null {
    const state = this.read();
    const link = state.mailboxLinks.find((candidate) => candidate.mailboxAccountKey === mailboxAccountKey);
    if (!link) return null;
    return structuredClone(state.accounts.find((candidate) => candidate.accountId === link.accountId) ?? null);
  }

  recordFamilyThreat(
    mailboxAccountKey: string,
    campaignFingerprint: string,
    source: FamilyThreatSource,
  ): FamilyThreatSnapshot | null {
    assertFingerprint(campaignFingerprint);
    const state = this.read();
    const link = state.mailboxLinks.find((candidate) => candidate.mailboxAccountKey === mailboxAccountKey);
    if (!link) return null;
    const account = state.accounts.find((candidate) => candidate.accountId === link.accountId);
    if (!account) return null;
    const circle = this.circleForAccount(state, account);
    if (!circle) return null;
    this.requireActiveFamily(state, circle);
    const now = this.runtime.now();
    let threat = circle.threats.find((candidate) => candidate.campaignFingerprint === campaignFingerprint);
    if (!threat) {
      if (circle.threats.length >= MAX_FAMILY_THREAT_CAMPAIGNS) {
        circle.threats.sort((left, right) => left.lastSeenAt - right.lastSeenAt);
        circle.threats.shift();
      }
      threat = {
        campaignFingerprint,
        reporterAccountIds: [],
        familyBlockerAccountIds: [],
        firstSeenAt: now,
        lastSeenAt: now,
      };
      circle.threats.push(threat);
    }
    threat.lastSeenAt = now;
    if (source === "report_scam") threat.reporterAccountIds = unique([...threat.reporterAccountIds, account.accountId]);
    else threat.familyBlockerAccountIds = unique([...threat.familyBlockerAccountIds, account.accountId]);
    this.write(state);
    return this.familyThreatSnapshot(mailboxAccountKey);
  }

  familyThreatSnapshot(mailboxAccountKey: string): FamilyThreatSnapshot | null {
    if (!/^[a-f0-9]{64}$/.test(mailboxAccountKey)) return null;
    const state = this.read();
    const link = state.mailboxLinks.find((candidate) => candidate.mailboxAccountKey === mailboxAccountKey);
    if (!link) return null;
    const account = state.accounts.find((candidate) => candidate.accountId === link.accountId);
    if (!account) return null;
    const circle = this.circleForAccount(state, account);
    if (!circle) return null;
    try { this.requireActiveFamily(state, circle); } catch { return null; }
    return {
      familyCircleId: circle.familyCircleId,
      accountId: account.accountId,
      entries: circle.threats.map((threat) => ({
        campaignFingerprint: threat.campaignFingerprint,
        status: familyThreatStatus(circle, threat),
      })),
    };
  }

  entitlementIsActive(): boolean {
    const state = this.read();
    return entitlementActive(this.current(state).entitlement, this.runtime.now());
  }
}
