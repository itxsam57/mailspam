import { afterEach, describe, expect, it } from "vitest";
import { generateKeyPairSync, sign } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { createAccountServiceServer } from "../../server/src/accountService/server.js";
import { SharedAccountFamilyService } from "../../server/src/accountService/service.js";
import { InMemoryAccountServiceStore } from "../../server/src/accountService/store.js";
import { HttpAccountFamilySyncClient } from "../../server/src/platform/httpAccountFamilySync.js";
import type { DeviceIdentityPort } from "../../server/src/platform/accountFamilyPorts.js";
import type { DevicePublicIdentity } from "../../server/src/platform/accountFamilyTypes.js";

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

function identity(label: string): DeviceIdentityPort {
  const pair = generateKeyPairSync("ed25519");
  const publicIdentity: DevicePublicIdentity = {
    algorithm: "ed25519",
    publicKeySpki: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    platform: "android",
    label,
  };
  return {
    currentPublicIdentity: async () => structuredClone(publicIdentity),
    signChallenge: async (challenge) => sign(null, Buffer.from(challenge, "utf8"), pair.privateKey).toString("base64"),
  };
}

describe("HTTP account/family sync adapter", () => {
  it("registers with device proof and performs signed snapshot/family operations", async () => {
    const service = new SharedAccountFamilyService(new InMemoryAccountServiceStore());
    const adminToken = "z".repeat(48);
    const server = createAccountServiceServer(service, { adminToken, allowDevelopmentEntitlements: true }).listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const accountId = "acct_adapter-00000001";
    const client = new HttpAccountFamilySyncClient(baseUrl, accountId, identity("Future Android shell"));

    const registered = await client.registerAccount("adapter.user", "adapter-recovery-code-123456789");
    expect(registered.account?.accountId).toBe(accountId);
    expect(registered.account?.entitlement.plan).toBe("free");

    const entitlementResponse = await fetch(`${baseUrl}/v1/internal/entitlements/${accountId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ entitlement: {
        plan: "family",
        status: "active",
        source: "development",
        productId: "email-shield-family-adapter-test",
        storeAccountReference: null,
        verifiedAt: Date.now(),
        expiresAt: null,
        graceUntil: null,
        seatLimit: 6,
      } }),
    });
    expect(entitlementResponse.status).toBe(200);

    const family = await client.createFamily();
    expect(family.family).toMatchObject({ seatsUsed: 1, seatLimit: 6 });
    const invite = await client.createInvite();
    expect(invite.inviteCode).toMatch(/^[A-Za-z0-9_-]{24,}$/);
    const snapshot = await client.snapshot();
    expect(snapshot.account.family?.familyCircleId).toBe(family.family?.familyCircleId);
  });

  it("refuses plaintext remote account service URLs", () => {
    expect(() => new HttpAccountFamilySyncClient(
      "http://example.com",
      "acct_adapter-00000002",
      identity("Remote phone"),
    )).toThrow(/requires HTTPS/i);
  });
});
