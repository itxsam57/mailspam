import { describe, expect, it } from "vitest";
import { AccountPlatformService } from "../../server/src/platform/accountFamilyService.js";
import { AccountLifecycleService } from "../../server/src/platform/accountLifecycleService.js";
import { InMemoryAccountPlatformRepository } from "../../server/src/platform/accountFamilyPersistence.js";
import type { AccountPlatformRuntime } from "../../server/src/platform/accountFamilyPorts.js";
import {
  deriveDeviceId,
  type DevicePublicIdentity,
  type VerifiedEntitlement,
} from "../../server/src/platform/accountFamilyTypes.js";

class Runtime implements AccountPlatformRuntime {
  nowValue = 2_000_000_000_000;
  private counter = 0;
  now() { return this.nowValue; }
  id(prefix: "acct" | "family" | "invite") { return `${prefix}_lifecycle-${++this.counter}`; }
  secret() { return `lifecycle-secret-${String(++this.counter).padStart(24, "0")}`; }
}

function identity(seed: string, label = `Device ${seed}`): DevicePublicIdentity {
  return {
    algorithm: "ed25519",
    publicKeySpki: Buffer.from(seed.repeat(64), "utf8").toString("base64"),
    platform: "desktop",
    label,
  };
}

function familyEntitlement(now: number): VerifiedEntitlement {
  return {
    plan: "family",
    status: "active",
    source: "development",
    productId: "email-shield-family-lifecycle-test",
    storeAccountReference: null,
    verifiedAt: now,
    expiresAt: null,
    graceUntil: null,
    seatLimit: 6,
  };
}

function setup() {
  const runtime = new Runtime();
  const repository = new InMemoryAccountPlatformRepository();
  return {
    runtime,
    repository,
    account: new AccountPlatformService(repository, runtime),
    lifecycle: new AccountLifecycleService(repository, runtime),
  };
}

describe("AccountLifecycleService", () => {
  it("rotates a recovery code atomically and invalidates the previous code", () => {
    const { account, lifecycle } = setup();
    const device = identity("a");
    const created = account.createAccount("rotate.owner", device);
    const rotated = lifecycle.rotateRecoveryCode(created.snapshot.deviceId);
    expect(rotated.recoveryCode).not.toBe(created.recoveryCode);

    expect(() => account.recoverAccount("rotate.owner", created.recoveryCode, identity("b"))).toThrow(/invalid/i);
    expect(account.recoverAccount("rotate.owner", rotated.recoveryCode, identity("b")).snapshot.signedIn).toBe(true);
  });

  it("revokes every other trusted device without weakening the current device", () => {
    const { account, lifecycle, runtime } = setup();
    const original = identity("a");
    const created = account.createAccount("devices.owner", original);
    const currentDeviceId = created.snapshot.deviceId;
    const other = identity("b");
    const otherDeviceId = deriveDeviceId(other);
    account.registerDevice(other, currentDeviceId);
    runtime.nowValue += 1_000;

    expect(lifecycle.revokeOtherDevices(currentDeviceId)).toEqual({ revoked: 1 });
    account.signOut();
    expect(account.signIn("devices.owner", currentDeviceId).signedIn).toBe(true);
    account.signOut();
    expect(() => account.signIn("devices.owner", otherDeviceId)).toThrow(/not registered/i);
  });

  it("signs out everywhere by revoking every device and requires recovery to return", () => {
    const { account, lifecycle } = setup();
    const first = identity("a");
    const created = account.createAccount("signout.everywhere", first);
    account.registerDevice(identity("b"), created.snapshot.deviceId);

    expect(lifecycle.signOutEverywhere(created.snapshot.deviceId)).toEqual({ revoked: 2 });
    expect(account.snapshot(created.snapshot.deviceId).signedIn).toBe(false);
    expect(() => account.signIn("signout.everywhere", created.snapshot.deviceId)).toThrow(/not registered/i);
    expect(account.recoverAccount("signout.everywhere", created.recoveryCode, identity("c")).snapshot.signedIn).toBe(true);
  });

  it("deletes a Family Shield circle explicitly and releases every member without leaking its threat history", () => {
    const { account, lifecycle, repository, runtime } = setup();
    const device = identity("a");
    const owner = account.createAccount("family.delete.owner", device);
    account.applyVerifiedEntitlement(familyEntitlement(runtime.now()), owner.snapshot.deviceId);
    account.createFamily(owner.snapshot.deviceId);
    const invite = account.createFamilyInvite();
    account.createAccount("family.delete.member", device);
    account.joinFamily(invite.inviteCode, owner.snapshot.deviceId);
    account.signIn("family.delete.owner", owner.snapshot.deviceId);

    const result = lifecycle.deleteFamilyCircle(owner.snapshot.deviceId);
    expect(result.releasedMembers).toBe(2);
    const state = repository.load();
    expect(state.familyCircles).toEqual([]);
    expect(state.accounts.every((candidate) => candidate.familyCircleId === null)).toBe(true);
  });

  it("exports only privacy-safe account metadata", () => {
    const { account, lifecycle } = setup();
    const created = account.createAccount("export.owner", identity("a"));
    const mailboxKey = "9".repeat(64);
    account.linkMailbox(mailboxKey);
    const exported = lifecycle.exportAccountMetadata(created.snapshot.deviceId);
    expect(exported.account.linkedMailboxCount).toBe(1);
    expect(exported.account.devices[0]?.current).toBe(true);
    const serialized = JSON.stringify(exported);
    expect(serialized).not.toContain(mailboxKey);
    expect(serialized).not.toMatch(/recoveryCodeHash|publicKeySpki/i);
    expect(exported.privacy).toBe("no_recovery_hash_no_public_keys_no_mailbox_identity_no_mail_content");
  });

  it("refuses owner-account deletion until Family Shield is explicitly deleted", () => {
    const { account, lifecycle, runtime } = setup();
    const created = account.createAccount("delete.family.owner", identity("a"));
    account.applyVerifiedEntitlement(familyEntitlement(runtime.now()), created.snapshot.deviceId);
    account.createFamily(created.snapshot.deviceId);
    expect(() => lifecycle.deleteAccount(created.snapshot.deviceId)).toThrow(/Delete or transfer the Family Shield circle/i);
  });

  it("deletes a non-owner profile, mailbox links and its family evidence without deleting mailbox content", () => {
    const { account, lifecycle, repository, runtime } = setup();
    const device = identity("a");
    const owner = account.createAccount("delete.owner", device);
    account.applyVerifiedEntitlement(familyEntitlement(runtime.now()), owner.snapshot.deviceId);
    account.createFamily(owner.snapshot.deviceId);
    const invite = account.createFamilyInvite();

    const member = account.createAccount("delete.member", device);
    account.joinFamily(invite.inviteCode, member.snapshot.deviceId);
    account.linkMailbox("7".repeat(64));
    account.recordFamilyThreat("7".repeat(64), "a".repeat(64), "report_scam");

    const deleted = lifecycle.deleteAccount(member.snapshot.deviceId);
    expect(deleted.removedMailboxLinks).toBe(1);
    const state = repository.load();
    expect(state.accounts.some((candidate) => candidate.accountId === member.snapshot.account?.accountId)).toBe(false);
    expect(state.mailboxLinks).toEqual([]);
    expect(state.familyCircles[0]?.members.some((candidate) => candidate.accountId === member.snapshot.account?.accountId)).toBe(false);
    expect(state.currentAccountId).toBeNull();
  });
});
