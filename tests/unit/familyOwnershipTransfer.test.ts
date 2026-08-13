import express from "express";
import { afterEach, describe, expect, it } from "vitest";
import { generateKeyPairSync, sign } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createAccountLifecycleServer } from "../../server/src/accountService/lifecycleServer.js";
import { SharedAccountFamilyService } from "../../server/src/accountService/service.js";
import { InMemoryAccountServiceStore } from "../../server/src/accountService/store.js";
import { AccountPlatformService } from "../../server/src/platform/accountFamilyService.js";
import { InMemoryAccountPlatformRepository } from "../../server/src/platform/accountFamilyPersistence.js";
import type { AccountPlatformRuntime } from "../../server/src/platform/accountFamilyPorts.js";
import { AccountLifecycleService } from "../../server/src/platform/accountLifecycleService.js";
import {
  deriveDeviceId,
  hashRecoveryCode,
  type DevicePublicIdentity,
  type RegisteredDevice,
  type VerifiedEntitlement,
} from "../../server/src/platform/accountFamilyTypes.js";

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

class Runtime implements AccountPlatformRuntime {
  nowValue = 2_000_000_000_000;
  private counter = 0;
  now() { return this.nowValue; }
  id(prefix: "acct" | "family" | "invite") { return `${prefix}_transfer-${++this.counter}`; }
  secret() { return `transfer-secret-${String(++this.counter).padStart(24, "0")}`; }
}

function identity(seed: string): DevicePublicIdentity {
  return {
    algorithm: "ed25519",
    publicKeySpki: Buffer.from(seed.repeat(64), "utf8").toString("base64"),
    platform: "desktop",
    label: `Device ${seed}`,
  };
}

function familyEntitlement(now: number, seatLimit = 6): VerifiedEntitlement {
  return {
    plan: "family",
    status: "active",
    source: "development",
    productId: "email-shield-family-transfer-test",
    storeAccountReference: null,
    verifiedAt: now,
    expiresAt: null,
    graceUntil: null,
    seatLimit,
  };
}

function domainSetup() {
  const runtime = new Runtime();
  const repository = new InMemoryAccountPlatformRepository();
  return {
    runtime,
    repository,
    account: new AccountPlatformService(repository, runtime),
    lifecycle: new AccountLifecycleService(repository, runtime),
  };
}

function cryptoDevice(label: string) {
  const pair = generateKeyPairSync("ed25519");
  const identity: DevicePublicIdentity = {
    algorithm: "ed25519",
    publicKeySpki: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    platform: "desktop",
    label,
  };
  const deviceId = deriveDeviceId(identity);
  const registered: RegisteredDevice = {
    ...identity,
    deviceId,
    createdAt: 2_000_000_000_000,
    lastSeenAt: 2_000_000_000_000,
    revokedAt: null,
  };
  return { pair, identity, deviceId, registered };
}

async function post(baseUrl: string, path: string, body: unknown) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { response, body: await response.json().catch(() => ({})) as Record<string, any> };
}

describe("Family Shield ownership transfer", () => {
  it("atomically changes the single owner and allows the former owner to delete only their own profile", () => {
    const { runtime, repository, account, lifecycle } = domainSetup();
    const ownerIdentity = identity("a");
    const owner = account.createAccount("transfer.owner", ownerIdentity);
    const ownerId = owner.snapshot.account!.accountId;
    account.applyVerifiedEntitlement(familyEntitlement(runtime.now()), owner.snapshot.deviceId);
    account.createFamily(owner.snapshot.deviceId);
    const invite = account.createFamilyInvite();

    const memberIdentity = identity("b");
    const member = account.createAccount("transfer.member", memberIdentity);
    const memberId = member.snapshot.account!.accountId;
    account.applyVerifiedEntitlement(familyEntitlement(runtime.now()), member.snapshot.deviceId);
    account.joinFamily(invite.inviteCode, member.snapshot.deviceId);
    account.signIn("transfer.owner", owner.snapshot.deviceId);

    const transferred = lifecycle.transferFamilyOwnership(owner.snapshot.deviceId, memberId);
    expect(transferred).toMatchObject({
      previousOwnerAccountId: ownerId,
      newOwnerAccountId: memberId,
      seatLimit: 6,
    });

    let state = repository.load();
    const circle = state.familyCircles[0]!;
    expect(circle.ownerAccountId).toBe(memberId);
    expect(circle.members.filter((entry) => entry.role === "owner")).toEqual([
      expect.objectContaining({ accountId: memberId, role: "owner" }),
    ]);
    expect(circle.members.find((entry) => entry.accountId === ownerId)?.role).toBe("member");

    const deleted = lifecycle.deleteAccount(owner.snapshot.deviceId);
    expect(deleted.deletedAccountId).toBe(ownerId);
    state = repository.load();
    expect(state.accounts.some((candidate) => candidate.accountId === ownerId)).toBe(false);
    expect(state.familyCircles[0]?.ownerAccountId).toBe(memberId);
    expect(state.familyCircles[0]?.members.map((entry) => entry.accountId)).toEqual([memberId]);
  });

  it("refuses transfer to a member whose entitlement cannot safely carry the family", () => {
    const { runtime, account, lifecycle } = domainSetup();
    const owner = account.createAccount("transfer.entitled.owner", identity("c"));
    account.applyVerifiedEntitlement(familyEntitlement(runtime.now()), owner.snapshot.deviceId);
    account.createFamily(owner.snapshot.deviceId);
    const invite = account.createFamilyInvite();

    const member = account.createAccount("transfer.free.member", identity("d"));
    const memberId = member.snapshot.account!.accountId;
    account.joinFamily(invite.inviteCode, member.snapshot.deviceId);
    account.signIn("transfer.entitled.owner", owner.snapshot.deviceId);

    expect(() => lifecycle.transferFamilyOwnership(owner.snapshot.deviceId, memberId)).toThrow(/active Family entitlement/i);
  });

  it("requires the current owner's device-signed single-use lifecycle challenge remotely", async () => {
    const owner = cryptoDevice("Owner device");
    const member = cryptoDevice("Member device");
    const ownerId = "acct_owner0001";
    const memberId = "acct_member001";
    const familyCircleId = "family_transfer001";
    const now = 2_000_000_000_000;
    const store = new InMemoryAccountServiceStore({
      schemaVersion: 1,
      accounts: [
        {
          accountId: ownerId,
          username: "remote.transfer.owner",
          createdAt: now,
          recoveryCodeHash: hashRecoveryCode("owner-recovery-code-123456789012"),
          devices: [owner.registered],
          entitlement: familyEntitlement(now),
          familyCircleId,
        },
        {
          accountId: memberId,
          username: "remote.transfer.member",
          createdAt: now,
          recoveryCodeHash: hashRecoveryCode("member-recovery-code-123456789012"),
          devices: [member.registered],
          entitlement: familyEntitlement(now),
          familyCircleId,
        },
      ],
      familyCircles: [{
        familyCircleId,
        ownerAccountId: ownerId,
        createdAt: now,
        strictProtection: false,
        members: [
          { accountId: ownerId, role: "owner", joinedAt: now },
          { accountId: memberId, role: "member", joinedAt: now },
        ],
        invitations: [],
        threats: [],
      }],
    });
    const shared = new SharedAccountFamilyService(store, () => now);
    const app = express();
    app.use(createAccountLifecycleServer(shared, store, { now: () => now }));
    const server = app.listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    const unauthenticated = await post(baseUrl, "/v1/lifecycle/family/transfer", {
      accountId: ownerId,
      targetAccountId: memberId,
      confirmation: "TRANSFER FAMILY",
    });
    expect(unauthenticated.response.status).toBe(401);

    const challenge = await post(baseUrl, "/v1/lifecycle/auth/challenge", {
      accountId: ownerId,
      deviceId: owner.deviceId,
      operation: "family:transfer",
    });
    expect(challenge.response.status).toBe(200);
    const signature = sign(null, Buffer.from(String(challenge.body.challenge)), owner.pair.privateKey).toString("base64");
    const transferred = await post(baseUrl, "/v1/lifecycle/family/transfer", {
      accountId: ownerId,
      targetAccountId: memberId,
      confirmation: "TRANSFER FAMILY",
      auth: { challengeId: challenge.body.challengeId, signature },
    });
    expect(transferred.response.status).toBe(200);
    expect(transferred.body).toMatchObject({
      familyCircleId,
      previousOwnerAccountId: ownerId,
      newOwnerAccountId: memberId,
      seatLimit: 6,
    });
    expect(store.load().familyCircles[0]).toMatchObject({ ownerAccountId: memberId });

    const replay = await post(baseUrl, "/v1/lifecycle/family/transfer", {
      accountId: ownerId,
      targetAccountId: memberId,
      confirmation: "TRANSFER FAMILY",
      auth: { challengeId: challenge.body.challengeId, signature },
    });
    expect(replay.response.status).toBe(401);
  });
});
