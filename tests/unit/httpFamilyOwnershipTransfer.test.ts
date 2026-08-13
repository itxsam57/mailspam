import express from "express";
import { afterEach, describe, expect, it } from "vitest";
import { generateKeyPairSync, sign } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createAccountLifecycleServer } from "../../server/src/accountService/lifecycleServer.js";
import { SharedAccountFamilyService } from "../../server/src/accountService/service.js";
import { InMemoryAccountServiceStore } from "../../server/src/accountService/store.js";
import { HttpAccountFamilySyncClient } from "../../server/src/platform/httpAccountFamilySync.js";
import type { DeviceIdentityPort } from "../../server/src/platform/accountFamilyPorts.js";
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

function device(label: string, now: number): { port: DeviceIdentityPort; registered: RegisteredDevice } {
  const pair = generateKeyPairSync("ed25519");
  const identity: DevicePublicIdentity = {
    algorithm: "ed25519",
    publicKeySpki: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    platform: "android",
    label,
  };
  return {
    port: {
      currentPublicIdentity: async () => structuredClone(identity),
      signChallenge: async (challenge) => sign(null, Buffer.from(challenge, "utf8"), pair.privateKey).toString("base64"),
    },
    registered: {
      ...identity,
      deviceId: deriveDeviceId(identity),
      createdAt: now,
      lastSeenAt: now,
      revokedAt: null,
    },
  };
}

function familyEntitlement(now: number): VerifiedEntitlement {
  return {
    plan: "family",
    status: "active",
    source: "development",
    productId: "email-shield-family-http-transfer-test",
    storeAccountReference: null,
    verifiedAt: now,
    expiresAt: null,
    graceUntil: null,
    seatLimit: 6,
  };
}

describe("portable HTTP Family ownership transfer", () => {
  it("uses the lifecycle challenge path and returns the validated ownership transition", async () => {
    const now = 2_000_000_000_000;
    const ownerId = "acct_httpowner001";
    const memberId = "acct_httpmember01";
    const familyCircleId = "family_httptransfer001";
    const owner = device("Owner phone", now);
    const member = device("Member phone", now);
    const store = new InMemoryAccountServiceStore({
      schemaVersion: 1,
      accounts: [
        {
          accountId: ownerId,
          username: "http.transfer.owner",
          createdAt: now,
          recoveryCodeHash: hashRecoveryCode("owner-http-recovery-code-123456789"),
          devices: [owner.registered],
          entitlement: familyEntitlement(now),
          familyCircleId,
        },
        {
          accountId: memberId,
          username: "http.transfer.member",
          createdAt: now,
          recoveryCodeHash: hashRecoveryCode("member-http-recovery-code-123456789"),
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
    const service = new SharedAccountFamilyService(store, () => now);
    const app = express();
    app.use(createAccountLifecycleServer(service, store, { now: () => now }));
    const server = app.listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    const client = new HttpAccountFamilySyncClient(baseUrl, ownerId, owner.port);
    const result = await client.transferFamilyOwnership(memberId);
    expect(result).toEqual({
      familyCircleId,
      previousOwnerAccountId: ownerId,
      newOwnerAccountId: memberId,
      seatLimit: 6,
    });
    expect(store.load().familyCircles[0]).toMatchObject({ ownerAccountId: memberId });
    expect(store.load().familyCircles[0]?.members.filter((entry) => entry.role === "owner")).toEqual([
      expect.objectContaining({ accountId: memberId }),
    ]);
  });
});
