import { generateKeyPairSync } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { createConsumerDesktopServer } from "../../server/src/api/consumerDesktopServer.js";
import { LocalSecurityManager } from "../../server/src/api/localSecurity.js";
import { AccountPlatformService } from "../../server/src/platform/accountFamilyService.js";
import { InMemoryAccountPlatformRepository } from "../../server/src/platform/accountFamilyPersistence.js";
import type { DeviceIdentityPort } from "../../server/src/platform/accountFamilyPorts.js";
import { AccountLifecycleService } from "../../server/src/platform/accountLifecycleService.js";
import {
  deriveDeviceId,
  type DevicePublicIdentity,
  type VerifiedEntitlement,
} from "../../server/src/platform/accountFamilyTypes.js";
import { NodeAccountPlatformRuntime } from "../../server/src/platform/desktopDeviceIdentity.js";

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

function identity(label: string): { publicIdentity: DevicePublicIdentity; port: DeviceIdentityPort & { currentDeviceId(): Promise<string> } } {
  const pair = generateKeyPairSync("ed25519");
  const publicIdentity: DevicePublicIdentity = {
    algorithm: "ed25519",
    publicKeySpki: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    platform: "desktop",
    label,
  };
  return {
    publicIdentity,
    port: {
      currentPublicIdentity: async () => structuredClone(publicIdentity),
      currentDeviceId: async () => deriveDeviceId(publicIdentity),
      signChallenge: async () => "unused-local-signature",
    },
  };
}

function familyEntitlement(now: number): VerifiedEntitlement {
  return {
    plan: "family",
    status: "active",
    source: "development",
    productId: "email-shield-family-local-transfer-test",
    storeAccountReference: null,
    verifiedAt: now,
    expiresAt: null,
    graceUntil: null,
    seatLimit: 6,
  };
}

async function mutationNonce(baseUrl: string, cookie: string, csrf: string): Promise<string> {
  const response = await fetch(`${baseUrl}/api/security/mutation-token`, {
    method: "POST",
    headers: {
      Cookie: cookie,
      Origin: baseUrl,
      Referer: `${baseUrl}/`,
      "X-Email-Shield-CSRF": csrf,
    },
  });
  expect(response.status).toBe(200);
  return ((await response.json()) as { nonce: string }).nonce;
}

describe("protected local Family ownership transfer API", () => {
  it("requires the desktop mutation boundary and changes only Family ownership", async () => {
    const repository = new InMemoryAccountPlatformRepository();
    const runtime = new NodeAccountPlatformRuntime();
    const account = new AccountPlatformService(repository, runtime);
    const ownerIdentity = identity("Owner desktop");
    const owner = account.createAccount("local.transfer.owner", ownerIdentity.publicIdentity);
    const ownerId = owner.snapshot.account!.accountId;
    account.applyVerifiedEntitlement(familyEntitlement(runtime.now()), owner.snapshot.deviceId);
    account.createFamily(owner.snapshot.deviceId);
    const invite = account.createFamilyInvite();

    const memberIdentity = identity("Member desktop");
    const member = account.createAccount("local.transfer.member", memberIdentity.publicIdentity);
    const memberId = member.snapshot.account!.accountId;
    account.applyVerifiedEntitlement(familyEntitlement(runtime.now()), member.snapshot.deviceId);
    account.joinFamily(invite.inviteCode, member.snapshot.deviceId);
    account.signIn("local.transfer.owner", owner.snapshot.deviceId);

    const app = createConsumerDesktopServer({
      security: new LocalSecurityManager(),
      accountPlatform: account,
      accountLifecycle: new AccountLifecycleService(repository, runtime),
      deviceIdentity: ownerIdentity.port,
    });
    const server = app.listen(0, "127.0.0.1");
    servers.push(server);
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

    const home = await fetch(baseUrl);
    const html = await home.text();
    const cookie = home.headers.get("set-cookie")?.split(";", 1)[0] ?? "";
    const csrf = html.match(/<meta name="email-shield-csrf" content="([^"]+)"/)?.[1] ?? "";
    expect(cookie).toMatch(/^email_shield_local_session=/);
    expect(csrf.length).toBeGreaterThanOrEqual(32);

    const missingNonce = await fetch(`${baseUrl}/api/profile/v1/family/transfer`, {
      method: "POST",
      headers: {
        Cookie: cookie,
        Origin: baseUrl,
        Referer: `${baseUrl}/`,
        "X-Email-Shield-CSRF": csrf,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ targetAccountId: memberId, confirmation: "TRANSFER FAMILY" }),
    });
    expect(missingNonce.status).toBe(409);

    const nonce = await mutationNonce(baseUrl, cookie, csrf);
    const response = await fetch(`${baseUrl}/api/profile/v1/family/transfer`, {
      method: "POST",
      headers: {
        Cookie: cookie,
        Origin: baseUrl,
        Referer: `${baseUrl}/`,
        "X-Email-Shield-CSRF": csrf,
        "X-Email-Shield-Nonce": nonce,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ targetAccountId: memberId, confirmation: "TRANSFER FAMILY" }),
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(await response.json()).toMatchObject({
      previousOwnerAccountId: ownerId,
      newOwnerAccountId: memberId,
      seatLimit: 6,
    });

    const circle = repository.load().familyCircles[0]!;
    expect(circle.ownerAccountId).toBe(memberId);
    expect(circle.members.filter((entry) => entry.role === "owner")).toEqual([
      expect.objectContaining({ accountId: memberId }),
    ]);
  });
});
