import { afterEach, describe, expect, it } from "vitest";
import { generateKeyPairSync, sign } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { accountRegistrationStatement } from "../../server/src/accountService/protocol.js";
import { createAccountServiceServer } from "../../server/src/accountService/server.js";
import { SharedAccountFamilyService } from "../../server/src/accountService/service.js";
import { InMemoryAccountServiceStore } from "../../server/src/accountService/store.js";
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

function device(label: string) {
  const pair = generateKeyPairSync("ed25519");
  const identity: DevicePublicIdentity = {
    algorithm: "ed25519",
    publicKeySpki: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    platform: "desktop",
    label,
  };
  const registered: RegisteredDevice = {
    ...identity,
    deviceId: deriveDeviceId(identity),
    createdAt: 1,
    lastSeenAt: 1,
    revokedAt: null,
  };
  return { pair, identity, registered };
}

function registrationBody(
  accountId: string,
  username: string,
  recoveryCode: string,
  deviceValue: ReturnType<typeof device>,
) {
  const recoveryCodeHash = hashRecoveryCode(recoveryCode);
  const deviceId = deriveDeviceId(deviceValue.identity);
  const statement = accountRegistrationStatement({ accountId, username, recoveryCodeHash, deviceId });
  const deviceProof = sign(null, Buffer.from(statement, "utf8"), deviceValue.pair.privateKey).toString("base64");
  return {
    accountId,
    username,
    recoveryCodeHash,
    device: deviceValue.identity,
    deviceProof,
  };
}

async function start() {
  const service = new SharedAccountFamilyService(new InMemoryAccountServiceStore());
  const app = createAccountServiceServer(service, {
    adminToken: "a".repeat(48),
    allowDevelopmentEntitlements: true,
  });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return {
    service,
    baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
  };
}

async function json(baseUrl: string, path: string, body: unknown, extraHeaders: Record<string, string> = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: path.startsWith("/v1/internal/") ? "PUT" : "POST",
    headers: { "Content-Type": "application/json", ...extraHeaders },
    body: JSON.stringify(body),
  });
  return { response, body: await response.json().catch(() => ({})) as Record<string, any> };
}

async function signed(
  baseUrl: string,
  accountId: string,
  deviceValue: ReturnType<typeof device>,
  operation: string,
  path: string,
  extra: Record<string, unknown> = {},
) {
  const challenge = await json(baseUrl, "/v1/auth/challenge", {
    accountId,
    deviceId: deviceValue.registered.deviceId,
    operation,
  });
  expect(challenge.response.status).toBe(200);
  const signature = sign(null, Buffer.from(String(challenge.body.challenge), "utf8"), deviceValue.pair.privateKey).toString("base64");
  const result = await json(baseUrl, path, {
    accountId,
    auth: { challengeId: challenge.body.challengeId, signature },
    ...extra,
  });
  return { ...result, challengeId: challenge.body.challengeId, signature };
}

function familyEntitlement(): VerifiedEntitlement {
  return {
    plan: "family",
    status: "active",
    source: "development",
    productId: "email-shield-family-api-test",
    storeAccountReference: null,
    verifiedAt: Date.now(),
    expiresAt: null,
    graceUntil: null,
    seatLimit: 6,
  };
}

describe("shared account and Family Shield service", () => {
  it("registers app-key devices, rejects hardware/mail content fields, and exposes no mailbox content", async () => {
    const test = await start();
    const owner = device("Owner phone");
    const registration = await json(
      test.baseUrl,
      "/v1/accounts/register",
      registrationBody("acct_owner-00000001", "owner.family", "owner-recovery-code-123456789", owner),
    );
    expect(registration.response.status).toBe(201);
    expect(registration.body.snapshot.account.entitlement.plan).toBe("free");
    const serialized = JSON.stringify(registration.body);
    expect(serialized).not.toMatch(/recoveryCodeHash|privateKey|mailbox|subject|bodyText/i);

    const rejected = await json(test.baseUrl, "/v1/accounts/register", {
      ...registrationBody("acct_bad-00000001", "bad.family", "bad-recovery-code-123456789", owner),
      subject: "this must never enter account sync",
    });
    expect(rejected.response.status).toBe(400);
    expect(String(rejected.body.error)).toMatch(/rejects mailbox field subject/i);
  });

  it("requires a device signature, consumes challenges once, and scopes a challenge to one operation", async () => {
    const test = await start();
    const owner = device("Owner phone");
    await json(
      test.baseUrl,
      "/v1/accounts/register",
      registrationBody("acct_auth-00000001", "auth.family", "auth-recovery-code-123456789", owner),
    );

    const first = await signed(test.baseUrl, "acct_auth-00000001", owner, "snapshot", "/v1/sync/snapshot");
    expect(first.response.status).toBe(200);

    const replay = await json(test.baseUrl, "/v1/sync/snapshot", {
      accountId: "acct_auth-00000001",
      auth: { challengeId: first.challengeId, signature: first.signature },
    });
    expect(replay.response.status).toBe(401);
    expect(String(replay.body.error)).toMatch(/already used/i);

    const challenge = await json(test.baseUrl, "/v1/auth/challenge", {
      accountId: "acct_auth-00000001",
      deviceId: owner.registered.deviceId,
      operation: "snapshot",
    });
    const signature = sign(null, Buffer.from(String(challenge.body.challenge)), owner.pair.privateKey).toString("base64");
    const wrongOperation = await json(test.baseUrl, "/v1/family/create", {
      accountId: "acct_auth-00000001",
      auth: { challengeId: challenge.body.challengeId, signature },
    });
    expect(wrongOperation.response.status).toBe(401);
    expect(String(wrongOperation.body.error)).toMatch(/scope/i);
  });

  it("keeps subscription authority server-side and synchronizes family membership/threats across independent devices", async () => {
    const test = await start();
    const owner = device("Owner iPhone");
    const member = device("Member Android");
    const ownerId = "acct_owner-00000002";
    const memberId = "acct_member-00000002";
    for (const entry of [
      { id: ownerId, username: "cloud.owner", device: owner },
      { id: memberId, username: "cloud.member", device: member },
    ]) {
      const registered = await json(
        test.baseUrl,
        "/v1/accounts/register",
        registrationBody(entry.id, entry.username, `${entry.username}-recovery-code-123456789`, entry.device),
      );
      expect(registered.response.status).toBe(201);
    }

    const unauthorizedEntitlement = await json(test.baseUrl, `/v1/internal/entitlements/${ownerId}`, { entitlement: familyEntitlement() });
    expect(unauthorizedEntitlement.response.status).toBe(401);
    const entitlement = await json(
      test.baseUrl,
      `/v1/internal/entitlements/${ownerId}`,
      { entitlement: familyEntitlement() },
      { Authorization: `Bearer ${"a".repeat(48)}` },
    );
    expect(entitlement.response.status).toBe(200);
    expect(entitlement.body.snapshot.account.entitlement.plan).toBe("family");

    const created = await signed(test.baseUrl, ownerId, owner, "family:create", "/v1/family/create");
    expect(created.response.status).toBe(201);
    expect(created.body.family.seatsUsed).toBe(1);
    const invitation = await signed(test.baseUrl, ownerId, owner, "family:invite", "/v1/family/invite");
    expect(invitation.response.status).toBe(201);
    const joined = await signed(test.baseUrl, memberId, member, "family:join", "/v1/family/join", { inviteCode: invitation.body.inviteCode });
    expect(joined.response.status).toBe(200);
    expect(joined.body.family.seatsUsed).toBe(2);

    const campaign = "c".repeat(64);
    const memberReport = await signed(test.baseUrl, memberId, member, "family:threat", "/v1/family/threat", {
      campaignFingerprint: campaign,
      source: "report_scam",
    });
    expect(memberReport.response.status).toBe(200);
    expect(memberReport.body.familyThreats.entries).toContainEqual({ campaignFingerprint: campaign, status: "warning" });

    const ownerSnapshot = await signed(test.baseUrl, ownerId, owner, "snapshot", "/v1/sync/snapshot");
    expect(ownerSnapshot.body.familyThreats.entries).toContainEqual({ campaignFingerprint: campaign, status: "warning" });

    const ownerReport = await signed(test.baseUrl, ownerId, owner, "family:threat", "/v1/family/threat", {
      campaignFingerprint: campaign,
      source: "report_scam",
    });
    expect(ownerReport.body.familyThreats.entries).toContainEqual({ campaignFingerprint: campaign, status: "confirmed" });

    const memberSnapshot = await signed(test.baseUrl, memberId, member, "snapshot", "/v1/sync/snapshot");
    expect(memberSnapshot.body.familyThreats.entries).toContainEqual({ campaignFingerprint: campaign, status: "confirmed" });
    expect(JSON.stringify(memberSnapshot.body.familyThreats)).not.toMatch(/subject|senderAddress|providerNativeId|bodyText|rawUrl/i);
  });
});
