import {
  createPublicKey,
  randomBytes,
  randomUUID,
  verify,
} from "node:crypto";
import type { AccountPlatformRepository } from "../platform/accountFamilyPorts.js";
import { AccountPlatformService } from "../platform/accountFamilyService.js";
import {
  ACCOUNT_PLATFORM_SCHEMA_VERSION,
  MAX_FAMILY_THREAT_CAMPAIGNS,
  defaultFreeEntitlement,
  deriveDeviceId,
  familySeatLimit,
  familyThreatStatus,
  normalizeDeviceLabel,
  normalizePublicKeySpki,
  normalizeUsername,
  type AccountPlatformState,
  type DevicePublicIdentity,
  type EmailShieldAccount,
  type FamilyThreatSnapshot,
  type FamilyThreatSource,
  type PublicAccountPlatformSnapshot,
  type RegisteredDevice,
  type VerifiedEntitlement,
} from "../platform/accountFamilyTypes.js";
import { NodeAccountPlatformRuntime } from "../platform/desktopDeviceIdentity.js";
import type { AccountServiceStore } from "./store.js";
import {
  ACCOUNT_SERVICE_CHALLENGE_TTL_MS,
  ACCOUNT_SERVICE_MAX_CHALLENGES,
  ACCOUNT_SERVICE_SCHEMA_VERSION,
  type AccountRegistrationInput,
  type AccountServiceAuthProof,
  type AccountServiceChallenge,
  type AccountServiceOperation,
  type AccountServiceState,
} from "./types.js";

const MAX_ACCOUNTS = 1_000_000;
const MAX_SIGNATURE_BYTES = 1024;

function accountId(value: unknown): string {
  if (typeof value !== "string" || !/^acct_[A-Za-z0-9_-]{8,160}$/.test(value)) throw new Error("Email Shield account ID is invalid.");
  return value;
}

function fingerprint(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw new Error("Family campaign fingerprint is invalid.");
  return value;
}

function recoveryHash(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) throw new Error("Recovery proof hash is invalid.");
  return value;
}

function normalizeRegistrationDevice(input: RegisteredDevice, now: number): RegisteredDevice {
  if (!input || typeof input !== "object") throw new Error("Device registration is required.");
  if (!["ed25519", "p256"].includes(input.algorithm)) throw new Error("Device key algorithm is invalid.");
  if (!["desktop", "ios", "android"].includes(input.platform)) throw new Error("Device platform is invalid.");
  const publicKeySpki = normalizePublicKeySpki(input.publicKeySpki);
  const expectedDeviceId = deriveDeviceId({ algorithm: input.algorithm, publicKeySpki });
  if (input.deviceId !== expectedDeviceId) throw new Error("Device ID does not match its cryptographic public key.");
  return {
    deviceId: expectedDeviceId,
    algorithm: input.algorithm,
    publicKeySpki,
    platform: input.platform,
    label: normalizeDeviceLabel(input.label),
    createdAt: now,
    lastSeenAt: now,
    revokedAt: null,
  };
}

class ScopedAccountRepository implements AccountPlatformRepository {
  readonly persistent: boolean;

  constructor(
    private readonly store: AccountServiceStore,
    private readonly selectedAccountId: string,
  ) {
    this.persistent = store.persistent;
  }

  load(): AccountPlatformState {
    const state = this.store.load();
    return {
      schemaVersion: ACCOUNT_PLATFORM_SCHEMA_VERSION,
      currentAccountId: this.selectedAccountId,
      accounts: structuredClone(state.accounts),
      familyCircles: structuredClone(state.familyCircles),
      mailboxLinks: [],
    };
  }

  save(state: AccountPlatformState): void {
    if (state.mailboxLinks.length !== 0) throw new Error("Shared account service must never persist mailbox-profile links.");
    if (state.currentAccountId !== null && state.currentAccountId !== this.selectedAccountId) {
      throw new Error("Shared account service attempted to switch authorization context.");
    }
    this.store.save({
      schemaVersion: ACCOUNT_SERVICE_SCHEMA_VERSION,
      accounts: structuredClone(state.accounts),
      familyCircles: structuredClone(state.familyCircles),
    });
  }
}

function activeDevice(account: EmailShieldAccount, deviceId: string): RegisteredDevice | null {
  return account.devices.find((device) => device.deviceId === deviceId && device.revokedAt === null) ?? null;
}

function verifyDeviceSignature(device: RegisteredDevice, challenge: string, signatureBase64: string): boolean {
  if (typeof signatureBase64 !== "string" || signatureBase64.length < 16 || signatureBase64.length > MAX_SIGNATURE_BYTES * 2) return false;
  let signature: Buffer;
  try { signature = Buffer.from(signatureBase64, "base64"); } catch { return false; }
  if (signature.length < 32 || signature.length > MAX_SIGNATURE_BYTES) return false;
  try {
    const key = createPublicKey({
      key: Buffer.from(device.publicKeySpki, "base64"),
      type: "spki",
      format: "der",
    });
    return device.algorithm === "ed25519"
      ? verify(null, Buffer.from(challenge, "utf8"), key, signature)
      : verify("sha256", Buffer.from(challenge, "utf8"), key, signature);
  } catch {
    return false;
  }
}

function publicFamilyThreatSnapshot(state: AccountServiceState, account: EmailShieldAccount): FamilyThreatSnapshot | null {
  if (!account.familyCircleId) return null;
  const circle = state.familyCircles.find((candidate) => candidate.familyCircleId === account.familyCircleId);
  if (!circle) return null;
  const owner = state.accounts.find((candidate) => candidate.accountId === circle.ownerAccountId);
  if (!owner || familySeatLimit(owner.entitlement, Date.now()) < 2) return null;
  return {
    familyCircleId: circle.familyCircleId,
    accountId: account.accountId,
    entries: circle.threats.map((threat) => ({
      campaignFingerprint: threat.campaignFingerprint,
      status: familyThreatStatus(circle, threat),
    })),
  };
}

export class SharedAccountFamilyService {
  private readonly challenges = new Map<string, AccountServiceChallenge>();
  private readonly runtime = new NodeAccountPlatformRuntime();

  constructor(
    private readonly store: AccountServiceStore,
    private readonly now: () => number = Date.now,
  ) {}

  persistent(): boolean { return this.store.persistent; }

  registerAccount(input: AccountRegistrationInput): PublicAccountPlatformSnapshot {
    const state = this.store.load();
    if (state.accounts.length >= MAX_ACCOUNTS) throw new Error("Account service capacity has been reached.");
    const normalizedAccountId = accountId(input.accountId);
    const username = normalizeUsername(input.username);
    if (state.accounts.some((candidate) => candidate.accountId === normalizedAccountId)) throw new Error("Email Shield account already exists.");
    if (state.accounts.some((candidate) => candidate.username === username)) throw new Error("Email Shield username is already registered.");
    const now = this.now();
    const account: EmailShieldAccount = {
      accountId: normalizedAccountId,
      username,
      createdAt: now,
      recoveryCodeHash: recoveryHash(input.recoveryCodeHash),
      devices: [normalizeRegistrationDevice(input.device, now)],
      entitlement: defaultFreeEntitlement(now),
      familyCircleId: null,
    };
    this.store.save({ ...state, accounts: [...state.accounts, account] });
    return this.scoped(normalizedAccountId).snapshot(account.devices[0]!.deviceId);
  }

  recoverAccount(input: {
    username: string;
    recoveryCode: string;
    device: DevicePublicIdentity;
  }): { recoveryCode: string; snapshot: PublicAccountPlatformSnapshot } {
    const state = this.store.load();
    const username = normalizeUsername(input.username);
    const account = state.accounts.find((candidate) => candidate.username === username);
    if (!account) throw new Error("The Email Shield recovery proof is invalid.");
    return this.scoped(account.accountId).recoverAccount(username, input.recoveryCode, input.device);
  }

  issueChallenge(accountIdInput: unknown, deviceIdInput: unknown, operation: AccountServiceOperation): AccountServiceChallenge {
    this.pruneChallenges();
    const normalizedAccountId = accountId(accountIdInput);
    if (typeof deviceIdInput !== "string" || !/^dev_[a-f0-9]{64}$/.test(deviceIdInput)) throw new Error("Device ID is invalid.");
    const state = this.store.load();
    const account = state.accounts.find((candidate) => candidate.accountId === normalizedAccountId);
    const device = account ? activeDevice(account, deviceIdInput) : null;
    if (!account || !device) throw new Error("Account/device pair is not registered.");
    if (this.challenges.size >= ACCOUNT_SERVICE_MAX_CHALLENGES) throw new Error("Authentication challenge capacity is temporarily full.");
    const challengeId = randomUUID();
    const createdAt = this.now();
    const nonce = randomBytes(32).toString("base64url");
    const challengeText = [
      "email-shield-account-service-auth-v1",
      challengeId,
      normalizedAccountId,
      device.deviceId,
      operation,
      nonce,
    ].join("\n");
    const challenge: AccountServiceChallenge = {
      challengeId,
      accountId: normalizedAccountId,
      deviceId: device.deviceId,
      operation,
      challenge: challengeText,
      createdAt,
      expiresAt: createdAt + ACCOUNT_SERVICE_CHALLENGE_TTL_MS,
      usedAt: null,
    };
    this.challenges.set(challengeId, challenge);
    return structuredClone(challenge);
  }

  authenticate(accountIdInput: unknown, operation: AccountServiceOperation, proof: AccountServiceAuthProof): {
    account: EmailShieldAccount;
    device: RegisteredDevice;
  } {
    const normalizedAccountId = accountId(accountIdInput);
    if (!proof || typeof proof.challengeId !== "string" || typeof proof.signature !== "string") throw new Error("Device authentication proof is required.");
    const challenge = this.challenges.get(proof.challengeId);
    if (!challenge || challenge.usedAt !== null) throw new Error("Authentication challenge is unknown or already used.");
    // Claim before signature verification so an attacker cannot brute-force one
    // challenge repeatedly or replay a successful proof concurrently.
    challenge.usedAt = this.now();
    if (challenge.expiresAt <= challenge.usedAt) throw new Error("Authentication challenge expired.");
    if (challenge.accountId !== normalizedAccountId || challenge.operation !== operation) throw new Error("Authentication challenge scope does not match this request.");
    const state = this.store.load();
    const account = state.accounts.find((candidate) => candidate.accountId === normalizedAccountId);
    const device = account ? activeDevice(account, challenge.deviceId) : null;
    if (!account || !device || !verifyDeviceSignature(device, challenge.challenge, proof.signature)) {
      throw new Error("Device signature verification failed.");
    }
    return { account: structuredClone(account), device: structuredClone(device) };
  }

  snapshot(accountIdInput: string, deviceId: string): PublicAccountPlatformSnapshot {
    return this.scoped(accountId(accountIdInput)).snapshot(deviceId);
  }

  createFamily(accountIdInput: string, deviceId: string): PublicAccountPlatformSnapshot {
    return this.scoped(accountId(accountIdInput)).createFamily(deviceId);
  }

  createFamilyInvite(accountIdInput: string): { inviteCode: string; expiresAt: number } {
    return this.scoped(accountId(accountIdInput)).createFamilyInvite();
  }

  joinFamily(accountIdInput: string, deviceId: string, inviteCode: string): PublicAccountPlatformSnapshot {
    return this.scoped(accountId(accountIdInput)).joinFamily(inviteCode, deviceId);
  }

  leaveFamily(accountIdInput: string, deviceId: string): PublicAccountPlatformSnapshot {
    return this.scoped(accountId(accountIdInput)).leaveFamily(deviceId);
  }

  setStrictFamilyProtection(accountIdInput: string, deviceId: string, enabled: boolean): PublicAccountPlatformSnapshot {
    return this.scoped(accountId(accountIdInput)).setStrictFamilyProtection(enabled, deviceId);
  }

  removeFamilyMember(accountIdInput: string, deviceId: string, memberAccountId: string): PublicAccountPlatformSnapshot {
    return this.scoped(accountId(accountIdInput)).removeFamilyMember(accountId(memberAccountId), deviceId);
  }

  recordFamilyThreat(accountIdInput: string, campaignFingerprintInput: string, source: FamilyThreatSource): FamilyThreatSnapshot | null {
    const normalizedAccountId = accountId(accountIdInput);
    const campaignFingerprint = fingerprint(campaignFingerprintInput);
    const state = this.store.load();
    const account = state.accounts.find((candidate) => candidate.accountId === normalizedAccountId);
    if (!account || !account.familyCircleId) return null;
    const circle = state.familyCircles.find((candidate) => candidate.familyCircleId === account.familyCircleId);
    if (!circle) return null;
    const owner = state.accounts.find((candidate) => candidate.accountId === circle.ownerAccountId);
    if (!owner || familySeatLimit(owner.entitlement, this.now()) < 2) throw new Error("Family Shield is paused because the owner does not have an active Family entitlement.");
    if (!circle.members.some((member) => member.accountId === normalizedAccountId)) throw new Error("Account is not an active member of this Family Shield circle.");

    const now = this.now();
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
    if (source === "report_scam") {
      threat.reporterAccountIds = [...new Set([...threat.reporterAccountIds, normalizedAccountId])];
    } else {
      threat.familyBlockerAccountIds = [...new Set([...threat.familyBlockerAccountIds, normalizedAccountId])];
    }
    this.store.save(state);
    return publicFamilyThreatSnapshot(this.store.load(), account);
  }

  familyThreatSnapshot(accountIdInput: string): FamilyThreatSnapshot | null {
    const normalizedAccountId = accountId(accountIdInput);
    const state = this.store.load();
    const account = state.accounts.find((candidate) => candidate.accountId === normalizedAccountId);
    return account ? publicFamilyThreatSnapshot(state, account) : null;
  }

  applyVerifiedEntitlement(accountIdInput: string, entitlement: VerifiedEntitlement): PublicAccountPlatformSnapshot {
    const normalizedAccountId = accountId(accountIdInput);
    const state = this.store.load();
    const account = state.accounts.find((candidate) => candidate.accountId === normalizedAccountId);
    if (!account) throw new Error("Unknown Email Shield account.");
    const device = account.devices.find((candidate) => candidate.revokedAt === null);
    if (!device) throw new Error("Account has no active device.");
    return this.scoped(normalizedAccountId).applyVerifiedEntitlement(entitlement, device.deviceId);
  }

  private scoped(selectedAccountId: string): AccountPlatformService {
    return new AccountPlatformService(new ScopedAccountRepository(this.store, selectedAccountId), this.runtime);
  }

  private pruneChallenges(): void {
    const now = this.now();
    for (const [id, challenge] of this.challenges) {
      if (challenge.expiresAt <= now || (challenge.usedAt !== null && challenge.usedAt + ACCOUNT_SERVICE_CHALLENGE_TTL_MS <= now)) {
        this.challenges.delete(id);
      }
    }
  }
}
