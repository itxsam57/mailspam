import express from "express";
import { afterEach, describe, expect, it } from "vitest";
import { generateKeyPairSync, sign } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { accountRegistrationStatement, accountRecoveryDeviceStatement } from "../../server/src/accountService/protocol.js";
import { createAccountLifecycleServer } from "../../server/src/accountService/lifecycleServer.js";
import { createAccountServiceServer } from "../../server/src/accountService/server.js";
import { SharedAccountFamilyService } from "../../server/src/accountService/service.js";
import { InMemoryAccountServiceStore } from "../../server/src/accountService/store.js";
import {
  deriveDeviceId,
  hashRecoveryCode,
  type DevicePublicIdentity,
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
  return { pair, identity, deviceId: deriveDeviceId(identity) };
}

function registration(accountId: string, username: string, recoveryCode: string, value: ReturnType<typeof device>) {
  const recoveryCodeHash = hashRecoveryCode(recoveryCode);
  const statement = accountRegistrationStatement({ accountId, username, recoveryCodeHash, deviceId: value.deviceId });
  return {
    accountId,
    username,
    recoveryCodeHash,
    device: value.identity,
    deviceProof: sign(null, Buffer.from(statement), value.pair.privateKey).toString("base64"),
  };
}

async function start() {
  const store = new InMemoryAccountServiceStore();
  const service = new SharedAccountFamilyService(store);
  const app = express();
  app.use(createAccountLifecycleServer(service, store));
  app.use(createAccountServiceServer(service, {
    adminToken: "a".repeat(48),
    allowDevelopmentEntitlements: true,
  }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return { store, service, baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

async function json(baseUrl: string, path: string, body: unknown, headers: Record<string, string> = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: path.startsWith("/v1/internal/") ? "PUT" : "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return { response, body: await response.json().catch(() => ({})) as Record<string, any> };
}

async function lifecycleSigned(
  baseUrl: string,
  accountId: string,
  value: ReturnType<typeof device>,
  operation: string,
  path: string,
  extra: Record<string, unknown> = {},
) {
  const challenge = await json(baseUrl, "/v1/lifecycle/auth/challenge", {
    accountId,
    deviceId: value.deviceId,
    operation,
  });
  expect(challenge.response.status).toBe(200);
  const signature = sign(null, Buffer.from(String(challenge.body.challenge)), value.pair.privateKey).toString("base64");
  const result = await json(baseUrl, path, {
    accountId,
    auth: { challengeId: challenge.body.challengeId, signature },
    ...extra,
  });
  return { ...result, challengeId: challenge.body.challengeId, signature };
}

async function baseSigned(
  baseUrl: string,
  accountId: string,
  value: ReturnType<typeof device>,
  operation: string,
  path: string,
  extra: Record<string, unknown> = {},
) {
  const challenge = await json(baseUrl, "/v1/auth/challenge", { accountId, deviceId: value.deviceId, operation });
  expect(challenge.response.status).toBe(200);
  const signature = sign(null, Buffer.from(String(challenge.body.challenge)), value.pair.privateKey).toString("base64");
  return json(baseUrl, path, {
    accountId,
    auth: { challengeId: challenge.body.challengeId, signature },
    ...extra,
  });
}

function familyEntitlement(): VerifiedEntitlement {
  return {
    plan: "family",
    status: "active",
    source: "development",
    productId: "email-shield-family-lifecycle-api",
    storeAccountReference: null,
    verifiedAt: Date.now(),
    expiresAt: null,
    graceUntil: null,
    seatLimit: 6,
  };
}

describe("device-signed account lifecycle service", () => {
  it("rotates recovery remotely and makes the previous recovery code unusable", async () => {
    const test = await start();
    const accountId = "acct_lifecycle-00000001";
    const owner = device("Owner desktop");
    const oldRecovery = "old-recovery-code-123456789012345";
    expect((await json(test.baseUrl, "/v1/accounts/register", registration(accountId, "lifecycle.owner", oldRecovery, owner))).response.status).toBe(201);

    const rotated = await lifecycleSigned(test.baseUrl, accountId, owner, "recovery:rotate", "/v1/lifecycle/recovery/rotate");
    expect(rotated.response.status).toBe(200);
    expect(String(rotated.body.recoveryCode)).not.toBe(oldRecovery);

    const recoveredDevice = device("Recovered desktop");
    const statement = accountRecoveryDeviceStatement({ username: "lifecycle.owner", deviceId: recoveredDevice.deviceId });
    const proof = sign(null, Buffer.from(statement), recoveredDevice.pair.privateKey).toString("base64");
    const oldAttempt = await json(test.baseUrl, "/v1/accounts/recover", {
      username: "lifecycle.owner",
      recoveryCode: oldRecovery,
      device: recoveredDevice.identity,
      deviceProof: proof,
    });
    // Established account-service contract classifies an invalid recovery code
    // as a 400 validation failure. The security invariant is that it is rejected.
    expect(oldAttempt.response.status).toBe(400);
    expect(String(oldAttempt.body.error)).toMatch(/recovery code is invalid/i);
    const newAttempt = await json(test.baseUrl, "/v1/accounts/recover", {
      username: "lifecycle.owner",
      recoveryCode: rotated.body.recoveryCode,
      device: recoveredDevice.identity,
      deviceProof: proof,
    });
    expect(newAttempt.response.status).toBe(200);
  });

  it("exports only account metadata and rejects mailbox/provider-secret fields before authentication", async () => {
    const test = await start();
    const accountId = "acct_lifecycle-00000002";
    const owner = device("Owner desktop");
    await json(test.baseUrl, "/v1/accounts/register", registration(accountId, "export.lifecycle", "export-recovery-code-123456789", owner));

    const exported = await lifecycleSigned(test.baseUrl, accountId, owner, "account:export", "/v1/lifecycle/account/export");
    expect(exported.response.status).toBe(200);
    const serialized = JSON.stringify(exported.body);
    expect(serialized).not.toMatch(/publicKeySpki|recoveryCodeHash|mailboxAccountKey|subject|bodyText/i);
    expect(exported.body.account.linkedMailboxCount).toBe(0);

    const rejected = await json(test.baseUrl, "/v1/lifecycle/account/export", {
      accountId,
      mailboxAccountKey: "f".repeat(64),
    });
    expect(rejected.response.status).toBe(400);
    expect(String(rejected.body.error)).toMatch(/rejects mailbox\/provider-secret field mailboxAccountKey/i);
  });

  it("consumes lifecycle challenges once", async () => {
    const test = await start();
    const accountId = "acct_lifecycle-00000003";
    const owner = device("Owner desktop");
    await json(test.baseUrl, "/v1/accounts/register", registration(accountId, "replay.lifecycle", "replay-recovery-code-123456789", owner));

    const first = await lifecycleSigned(test.baseUrl, accountId, owner, "devices:revoke-others", "/v1/lifecycle/devices/revoke-others");
    expect(first.response.status).toBe(200);
    const replay = await json(test.baseUrl, "/v1/lifecycle/devices/revoke-others", {
      accountId,
      auth: { challengeId: first.challengeId, signature: first.signature },
    });
    expect(replay.response.status).toBe(401);
    expect(String(replay.body.error)).toMatch(/already used/i);
  });

  it("deletes a Family circle only after an owner-signed challenge and explicit confirmation", async () => {
    const test = await start();
    const accountId = "acct_lifecycle-00000004";
    const owner = device("Owner desktop");
    await json(test.baseUrl, "/v1/accounts/register", registration(accountId, "delete.family.lifecycle", "family-recovery-code-123456789", owner));
    const entitlement = await json(
      test.baseUrl,
      `/v1/internal/entitlements/${accountId}`,
      { entitlement: familyEntitlement() },
      { Authorization: `Bearer ${"a".repeat(48)}` },
    );
    expect(entitlement.response.status).toBe(200);
    expect((await baseSigned(test.baseUrl, accountId, owner, "family:create", "/v1/family/create")).response.status).toBe(201);

    const challenge = await json(test.baseUrl, "/v1/lifecycle/auth/challenge", {
      accountId,
      deviceId: owner.deviceId,
      operation: "family:delete",
    });
    const signature = sign(null, Buffer.from(String(challenge.body.challenge)), owner.pair.privateKey).toString("base64");
    const missing = await json(test.baseUrl, "/v1/lifecycle/family/delete", {
      accountId,
      auth: { challengeId: challenge.body.challengeId, signature },
    });
    expect(missing.response.status).toBe(409);

    const deleted = await lifecycleSigned(test.baseUrl, accountId, owner, "family:delete", "/v1/lifecycle/family/delete", {
      confirmation: "DELETE FAMILY",
    });
    expect(deleted.response.status).toBe(200);
    expect(deleted.body.deletedFamilyCircleId).toMatch(/^family_/);
  });

  it("sign-out-everywhere revokes the signing device only after its authenticated request succeeds", async () => {
    const test = await start();
    const accountId = "acct_lifecycle-00000005";
    const owner = device("Owner desktop");
    await json(test.baseUrl, "/v1/accounts/register", registration(accountId, "signout.lifecycle", "signout-recovery-code-123456789", owner));
    const result = await lifecycleSigned(test.baseUrl, accountId, owner, "devices:signout-everywhere", "/v1/lifecycle/signout-everywhere");
    expect(result.response.status).toBe(200);
    expect(result.body.revoked).toBe(1);
    const challengeAfter = await json(test.baseUrl, "/v1/lifecycle/auth/challenge", {
      accountId,
      deviceId: owner.deviceId,
      operation: "account:export",
    });
    expect(challengeAfter.response.status).toBe(401);
  });

  it("account deletion removes the shared account without claiming to delete mailbox content", async () => {
    const test = await start();
    const accountId = "acct_lifecycle-00000006";
    const owner = device("Owner desktop");
    await json(test.baseUrl, "/v1/accounts/register", registration(accountId, "delete.account.lifecycle", "delete-recovery-code-123456789", owner));
    const deleted = await lifecycleSigned(test.baseUrl, accountId, owner, "account:delete", "/v1/lifecycle/account/delete", {
      confirmation: "DELETE ACCOUNT",
    });
    expect(deleted.response.status).toBe(200);
    expect(deleted.body).toMatchObject({
      deletedAccountId: accountId,
      mailboxContentDeleted: false,
      mailboxIdentityStoredByService: false,
    });
    expect(test.store.load().accounts).toEqual([]);
  });
});
