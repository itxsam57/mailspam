import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { AccountPlatformService } from "../../server/src/platform/accountFamilyService.js";
import { InMemoryAccountPlatformRepository } from "../../server/src/platform/accountFamilyPersistence.js";
import type { AccountPlatformRuntime } from "../../server/src/platform/accountFamilyPorts.js";
import {
  deriveDeviceId,
  normalizeUsername,
  type DevicePublicIdentity,
  type VerifiedEntitlement,
} from "../../server/src/platform/accountFamilyTypes.js";

class Runtime implements AccountPlatformRuntime {
  nowValue = 1_900_000_000_000;
  private counter = 0;
  now() { return this.nowValue; }
  id(prefix: "acct" | "family" | "invite") { return `${prefix}_test-identifier-${++this.counter}`; }
  secret() { return `test-secret-${String(++this.counter).padStart(20, "0")}`; }
}

function identity(seed = "a", label = "Test desktop"): DevicePublicIdentity {
  return {
    algorithm: "ed25519",
    publicKeySpki: Buffer.from(seed.repeat(64), "utf8").toString("base64"),
    platform: "desktop",
    label,
  };
}

function familyEntitlement(now: number, seats = 6): VerifiedEntitlement {
  return {
    plan: "family",
    status: "active",
    source: "development",
    productId: "email-shield-family-test",
    storeAccountReference: null,
    verifiedAt: now,
    expiresAt: null,
    graceUntil: null,
    seatLimit: seats,
  };
}

const ownerMailbox = "1".repeat(64);
const memberMailbox = "2".repeat(64);
const campaign = "a".repeat(64);

describe("portable Email Shield account and Family Shield domain", () => {
  it("normalizes usernames and rejects reserved/tracking-like invalid identities", () => {
    expect(normalizeUsername("  Sam.User  ")).toBe("sam.user");
    expect(() => normalizeUsername("admin")).toThrow(/reserved/i);
    expect(() => normalizeUsername("two words")).toThrow(/may contain/i);
  });

  it("derives stable device IDs from app cryptographic public identity, not a hardware ID", () => {
    const first = deriveDeviceId(identity("a"));
    expect(deriveDeviceId(identity("a"))).toBe(first);
    expect(deriveDeviceId(identity("b"))).not.toBe(first);
    expect(first).toMatch(/^dev_[a-f0-9]{64}$/);
  });

  it("creates Free accounts, signs in only on registered device and rotates recovery codes", () => {
    const runtime = new Runtime();
    const service = new AccountPlatformService(new InMemoryAccountPlatformRepository(), runtime);
    const originalIdentity = identity("a");
    const created = service.createAccount("family.owner", originalIdentity);
    const deviceId = deriveDeviceId(originalIdentity);
    expect(created.snapshot.account?.entitlement.plan).toBe("free");
    expect(created.snapshot.deviceId).toBe(deviceId);

    service.signOut();
    expect(service.signIn("family.owner", deviceId).signedIn).toBe(true);
    expect(() => service.signIn("family.owner", deriveDeviceId(identity("z")))).toThrow(/not registered/i);

    const recovered = service.recoverAccount("family.owner", created.recoveryCode, identity("b", "Recovered laptop"));
    expect(recovered.recoveryCode).not.toBe(created.recoveryCode);
    expect(() => service.recoverAccount("family.owner", created.recoveryCode, identity("c"))).toThrow(/invalid/i);
  });

  it("never permits revoking the last active trusted device", () => {
    const runtime = new Runtime();
    const service = new AccountPlatformService(new InMemoryAccountPlatformRepository(), runtime);
    const firstIdentity = identity("a");
    const created = service.createAccount("single.device", firstIdentity);
    expect(() => service.revokeDevice(created.snapshot.deviceId, created.snapshot.deviceId)).toThrow(/at least one trusted device/i);
  });

  it("requires an active Family entitlement and enforces its seat limit", () => {
    const runtime = new Runtime();
    const service = new AccountPlatformService(new InMemoryAccountPlatformRepository(), runtime);
    const device = identity("a");
    const created = service.createAccount("owner.one", device);
    expect(() => service.createFamily(created.snapshot.deviceId)).toThrow(/Family entitlement/i);

    service.applyVerifiedEntitlement(familyEntitlement(runtime.now(), 2), created.snapshot.deviceId);
    service.createFamily(created.snapshot.deviceId);
    const invitation = service.createFamilyInvite();
    service.createAccount("member.one", device);
    service.joinFamily(invitation.inviteCode, created.snapshot.deviceId);
    service.signIn("owner.one", created.snapshot.deviceId);
    expect(() => service.createFamilyInvite()).toThrow(/seats/i);
  });

  it("uses one-time expiring invitations", () => {
    const runtime = new Runtime();
    const service = new AccountPlatformService(new InMemoryAccountPlatformRepository(), runtime);
    const device = identity("a");
    const owner = service.createAccount("invite.owner", device);
    service.applyVerifiedEntitlement(familyEntitlement(runtime.now()), owner.snapshot.deviceId);
    service.createFamily(owner.snapshot.deviceId);
    const invite = service.createFamilyInvite();

    service.createAccount("invite.member", device);
    service.joinFamily(invite.inviteCode, owner.snapshot.deviceId);
    service.signOut();
    service.signIn("invite.member", owner.snapshot.deviceId);
    expect(() => service.joinFamily(invite.inviteCode, owner.snapshot.deviceId)).toThrow(/already belongs/i);

    service.signIn("invite.owner", owner.snapshot.deviceId);
    const expiring = service.createFamilyInvite();
    service.createAccount("late.member", device);
    runtime.nowValue = expiring.expiresAt + 1;
    expect(() => service.joinFamily(expiring.inviteCode, owner.snapshot.deviceId)).toThrow(/invalid, expired or already used/i);
  });

  it("creates a family warning from one member and confirms only after independent family evidence", () => {
    const runtime = new Runtime();
    const service = new AccountPlatformService(new InMemoryAccountPlatformRepository(), runtime);
    const device = identity("a");
    const owner = service.createAccount("shield.owner", device);
    service.applyVerifiedEntitlement(familyEntitlement(runtime.now()), owner.snapshot.deviceId);
    service.createFamily(owner.snapshot.deviceId);
    service.linkMailbox(ownerMailbox);
    const invite = service.createFamilyInvite();

    service.createAccount("shield.member", device);
    service.joinFamily(invite.inviteCode, owner.snapshot.deviceId);
    service.linkMailbox(memberMailbox);
    const first = service.recordFamilyThreat(memberMailbox, campaign, "report_scam");
    expect(first?.entries).toContainEqual({ campaignFingerprint: campaign, status: "warning" });

    service.signIn("shield.owner", owner.snapshot.deviceId);
    const second = service.recordFamilyThreat(ownerMailbox, campaign, "report_scam");
    expect(second?.entries).toContainEqual({ campaignFingerprint: campaign, status: "confirmed" });
  });

  it("supports Strict Family Protection without turning private family evidence into a global rule", () => {
    const runtime = new Runtime();
    const service = new AccountPlatformService(new InMemoryAccountPlatformRepository(), runtime);
    const device = identity("a");
    const owner = service.createAccount("strict.owner", device);
    service.applyVerifiedEntitlement(familyEntitlement(runtime.now()), owner.snapshot.deviceId);
    service.createFamily(owner.snapshot.deviceId);
    service.setStrictFamilyProtection(true, owner.snapshot.deviceId);
    service.linkMailbox(ownerMailbox);
    const snapshot = service.recordFamilyThreat(ownerMailbox, campaign, "report_scam");
    expect(snapshot?.entries[0]).toEqual({ campaignFingerprint: campaign, status: "confirmed" });
    expect(JSON.stringify(snapshot)).not.toMatch(/subject|body|sender|providerNativeId|mailboxAddress/i);
  });

  it("keeps the portable account/family domain free of Node, Express, provider and browser dependencies", () => {
    const root = join(import.meta.dirname, "../../server/src/platform");
    for (const file of ["accountFamilyTypes.ts", "accountFamilyPorts.ts", "accountFamilyService.ts", "familyThreatProtocol.ts"]) {
      const source = readFileSync(join(root, file), "utf8");
      expect(source).not.toMatch(/node:|express|imap|gmail|outlook|document\.|window\.|localStorage|sessionStorage/i);
    }
  });
});
