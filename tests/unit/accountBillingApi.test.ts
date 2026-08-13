import express from "express";
import { afterEach, describe, expect, it } from "vitest";
import { generateKeyPairSync, sign } from "node:crypto";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { accountRegistrationStatement } from "../../server/src/accountService/protocol.js";
import { createAccountBillingServer } from "../../server/src/accountService/billingServer.js";
import { createAccountServiceServer } from "../../server/src/accountService/server.js";
import { SharedAccountFamilyService } from "../../server/src/accountService/service.js";
import { InMemoryAccountServiceStore } from "../../server/src/accountService/store.js";
import {
  BillingEntitlementCoordinator,
  InMemoryBillingEventLedger,
  type BillingEvidence,
  type BillingEntitlementPolicy,
  type BillingVerifierPort,
  type VerifiedBillingEvent,
} from "../../server/src/billing/billingVerification.js";
import {
  deriveDeviceId,
  hashRecoveryCode,
  type DevicePublicIdentity,
} from "../../server/src/platform/accountFamilyTypes.js";

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

function testDevice() {
  const pair = generateKeyPairSync("ed25519");
  const identity: DevicePublicIdentity = {
    algorithm: "ed25519",
    publicKeySpki: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    platform: "desktop",
    label: "Billing test device",
  };
  return { pair, identity, deviceId: deriveDeviceId(identity) };
}

async function post(baseUrl: string, path: string, body: unknown) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { response, body: await response.json().catch(() => ({})) as Record<string, any> };
}

async function register(baseUrl: string, accountId: string, username: string, device: ReturnType<typeof testDevice>) {
  const recoveryCodeHash = hashRecoveryCode("billing-test-recovery-code-123456789");
  const statement = accountRegistrationStatement({ accountId, username, recoveryCodeHash, deviceId: device.deviceId });
  const deviceProof = sign(null, Buffer.from(statement, "utf8"), device.pair.privateKey).toString("base64");
  const result = await post(baseUrl, "/v1/accounts/register", {
    accountId,
    username,
    recoveryCodeHash,
    device: device.identity,
    deviceProof,
  });
  expect(result.response.status).toBe(201);
}

async function billingAuth(
  baseUrl: string,
  accountId: string,
  device: ReturnType<typeof testDevice>,
) {
  const challenge = await post(baseUrl, "/v1/auth/challenge", {
    accountId,
    deviceId: device.deviceId,
    operation: "billing:verify",
  });
  expect(challenge.response.status).toBe(200);
  const signature = sign(null, Buffer.from(String(challenge.body.challenge), "utf8"), device.pair.privateKey).toString("base64");
  return { challengeId: String(challenge.body.challengeId), signature };
}

async function signedBillingVerify(
  baseUrl: string,
  accountId: string,
  device: ReturnType<typeof testDevice>,
  evidence: BillingEvidence,
) {
  return post(baseUrl, "/v1/billing/verify", {
    accountId,
    auth: await billingAuth(baseUrl, accountId, device),
    evidence,
  });
}

async function start(enabled: boolean) {
  const store = new InMemoryAccountServiceStore();
  const service = new SharedAccountFamilyService(store);
  const allowedProductId = "com.emailshield.family.monthly";
  const policy: BillingEntitlementPolicy = {
    productPlan(productId) {
      return productId === allowedProductId ? { plan: "family", seatLimit: 6 } : null;
    },
    maximumOfflineCacheAgeMs: 72 * 60 * 60 * 1_000,
    maximumGraceMs: 16 * 24 * 60 * 60 * 1_000,
  };
  let verifierCalls = 0;
  const verifier: BillingVerifierPort = {
    store: "google",
    async verify(evidence) {
      verifierCalls += 1;
      const event: VerifiedBillingEvent = {
        store: "google",
        eventId: evidence.eventId,
        eventType: evidence.eventType,
        plan: "family",
        productId: evidence.productId,
        storeAccountReference: evidence.storeAccountReference,
        purchaseReference: evidence.purchaseReference,
        occurredAt: evidence.occurredAt,
        expiresAt: evidence.expiresAt,
        graceUntil: evidence.graceUntil,
        originalPurchaseReference: evidence.originalPurchaseReference,
        familyTransferFromAccountReference: evidence.familyTransferFromAccountReference,
        verifiedBy: "test-google-verifier",
      };
      return event;
    },
  };
  const coordinator = enabled
    ? new BillingEntitlementCoordinator(
        new Map([["google", verifier]]),
        new InMemoryBillingEventLedger(),
        (accountId, entitlement) => { void service.applyVerifiedEntitlement(accountId, entitlement); },
        policy,
      )
    : null;
  const app = express();
  app.use(createAccountBillingServer(service, coordinator, { enabled }));
  app.use(createAccountServiceServer(service, { adminToken: "a".repeat(48), allowDevelopmentEntitlements: false }));
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  return {
    baseUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    service,
    allowedProductId,
    verifierCalls: () => verifierCalls,
  };
}

function evidence(productId: string, suffix = "001"): BillingEvidence {
  const now = Date.now();
  return {
    store: "google",
    eventId: `google-event-${suffix}`,
    eventType: "purchase",
    productId,
    storeAccountReference: "google-account-ref",
    purchaseReference: `google-purchase-ref-${suffix}`,
    occurredAt: now - 1_000,
    expiresAt: now + 30 * 24 * 60 * 60 * 1_000,
    graceUntil: null,
    originalPurchaseReference: null,
    familyTransferFromAccountReference: null,
    verificationPayload: "opaque-google-purchase-evidence",
  };
}

describe("account-service billing verification", () => {
  it("stays free-only when the paid-plan kill switch is disabled", async () => {
    const test = await start(false);
    const status = await fetch(`${test.baseUrl}/v1/billing/status`);
    expect(status.status).toBe(200);
    expect(await status.json()).toMatchObject({ enabled: false, verification: "disabled_free_only", clientSecretsAccepted: false });

    const device = testDevice();
    const accountId = "acct_billing-disabled";
    await register(test.baseUrl, accountId, "billing.disabled", device);
    const challenge = await post(test.baseUrl, "/v1/auth/challenge", { accountId, deviceId: device.deviceId, operation: "billing:verify" });
    expect(challenge.response.status).toBe(503);
    expect(test.service.snapshot(accountId, device.deviceId).account?.entitlement.plan).toBe("free");
  });

  it("requires a signed device challenge, verifies an exact allowed SKU, and treats replay as duplicate", async () => {
    const test = await start(true);
    const device = testDevice();
    const accountId = "acct_billing-enabled";
    await register(test.baseUrl, accountId, "billing.enabled", device);
    const storeEvidence = evidence(test.allowedProductId);

    const unauthenticated = await post(test.baseUrl, "/v1/billing/verify", {
      accountId,
      auth: { challengeId: "missing", signature: "missing" },
      evidence: storeEvidence,
    });
    expect(unauthenticated.response.status).toBe(401);

    const first = await signedBillingVerify(test.baseUrl, accountId, device, storeEvidence);
    expect(first.response.status).toBe(200);
    expect(first.body.verified).toBe(true);
    expect(first.body.duplicateEvent).toBe(false);
    expect(first.body.entitlement).toMatchObject({ plan: "family", status: "active", source: "google", seatLimit: 6 });
    expect(first.body.snapshot.account.entitlement.plan).toBe("family");

    const replay = await signedBillingVerify(test.baseUrl, accountId, device, storeEvidence);
    expect(replay.response.status).toBe(200);
    expect(replay.body.duplicateEvent).toBe(true);
    expect(test.verifierCalls()).toBe(2);
  });

  it("rejects a store-verified product that is not on Email Shield's exact SKU allowlist", async () => {
    const test = await start(true);
    const device = testDevice();
    const accountId = "acct_billing-wrong-sku";
    await register(test.baseUrl, accountId, "billing.wrongsku", device);
    const result = await signedBillingVerify(test.baseUrl, accountId, device, evidence("com.fake.family.monthly", "wrong-sku"));
    expect(result.response.status).toBe(400);
    expect(String(result.body.error)).toMatch(/product/i);
    expect(test.service.snapshot(accountId, device.deviceId).account?.entitlement.plan).toBe("free");
  });

  it("rejects unknown billing evidence fields before calling the store verifier", async () => {
    const test = await start(true);
    const device = testDevice();
    const accountId = "acct_billing-unknown-field";
    await register(test.baseUrl, accountId, "billing.unknownfield", device);
    const auth = await billingAuth(test.baseUrl, accountId, device);
    const result = await post(test.baseUrl, "/v1/billing/verify", {
      accountId,
      auth,
      evidence: {
        ...evidence(test.allowedProductId, "unknown-field"),
        mailboxAddress: "must-not-be-forwarded@example.test",
      },
    });
    expect(result.response.status).toBe(400);
    expect(String(result.body.error)).toMatch(/unsupported fields/i);
    expect(test.verifierCalls()).toBe(0);
    expect(test.service.snapshot(accountId, device.deviceId).account?.entitlement.plan).toBe("free");
  });

  it("bounds billing challenge abuse per client before challenge state can grow without limit", async () => {
    const test = await start(true);
    const device = testDevice();
    const accountId = "acct_billing-rate-limit";
    await register(test.baseUrl, accountId, "billing.ratelimit", device);

    for (let index = 0; index < 30; index += 1) {
      const result = await post(test.baseUrl, "/v1/auth/challenge", {
        accountId,
        deviceId: device.deviceId,
        operation: "billing:verify",
      });
      expect(result.response.status).toBe(200);
    }
    const limited = await post(test.baseUrl, "/v1/auth/challenge", {
      accountId,
      deviceId: device.deviceId,
      operation: "billing:verify",
    });
    expect(limited.response.status).toBe(429);
    expect(limited.response.headers.get("retry-after")).toBeTruthy();
  });
});
