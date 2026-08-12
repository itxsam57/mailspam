import { generateKeyPairSync, sign } from "node:crypto";
import { accountRegistrationStatement } from "../../server/dist/accountService/protocol.js";
import { createAccountServiceServer } from "../../server/dist/accountService/server.js";
import { SharedAccountFamilyService } from "../../server/dist/accountService/service.js";
import { InMemoryAccountServiceStore } from "../../server/dist/accountService/store.js";
import { deriveDeviceId, hashRecoveryCode } from "../../server/dist/platform/accountFamilyTypes.js";

const pair = generateKeyPairSync("ed25519");
const identity = {
  algorithm: "ed25519",
  publicKeySpki: pair.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
  platform: "desktop",
  label: "Compiled smoke device",
};
const deviceId = deriveDeviceId(identity);
const accountId = "acct_smoke-account-0001";
const username = "compiled.smoke";
const recoveryCodeHash = hashRecoveryCode("compiled-smoke-recovery-code-123456789");
const registrationStatement = accountRegistrationStatement({ accountId, username, recoveryCodeHash, deviceId });
const registrationProof = sign(null, Buffer.from(registrationStatement, "utf8"), pair.privateKey).toString("base64");
const adminToken = "account-service-smoke-admin-token-1234567890";
const service = new SharedAccountFamilyService(new InMemoryAccountServiceStore());
const app = createAccountServiceServer(service, { adminToken, allowDevelopmentEntitlements: true });
const server = app.listen(0, "127.0.0.1");
await new Promise((resolve, reject) => {
  server.once("listening", resolve);
  server.once("error", reject);
});
const port = server.address().port;
const baseUrl = `http://127.0.0.1:${port}`;

async function request(path, body, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    method: options.method || "POST",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const parsed = await response.json().catch(() => ({}));
  if (options.expect !== undefined && response.status !== options.expect) {
    throw new Error(`${path} returned ${response.status}, expected ${options.expect}: ${JSON.stringify(parsed)}`);
  }
  return { response, body: parsed };
}

try {
  const status = await fetch(`${baseUrl}/v1/status`);
  if (!status.ok) throw new Error("Account service status route failed.");
  const statusBody = await status.json();
  if (statusBody.mailContentAccepted !== false || statusBody.auth !== "device-signed-single-use-challenge") {
    throw new Error("Account service status did not preserve privacy/authentication contracts.");
  }

  await request("/v1/accounts/register", {
    accountId,
    username,
    recoveryCodeHash,
    device: identity,
    deviceProof: registrationProof,
  }, { expect: 201 });

  await request(`/v1/internal/entitlements/${accountId}`, {
    entitlement: {
      plan: "family",
      status: "active",
      source: "development",
      productId: "email-shield-family-smoke",
      storeAccountReference: null,
      verifiedAt: Date.now(),
      expiresAt: null,
      graceUntil: null,
      seatLimit: 6,
    },
  }, { expect: 200, method: "PUT", headers: { Authorization: `Bearer ${adminToken}` } });

  const challenge = await request("/v1/auth/challenge", {
    accountId,
    deviceId,
    operation: "family:create",
  }, { expect: 200 });
  const signature = sign(null, Buffer.from(challenge.body.challenge, "utf8"), pair.privateKey).toString("base64");
  const family = await request("/v1/family/create", {
    accountId,
    auth: { challengeId: challenge.body.challengeId, signature },
  }, { expect: 201 });
  if (family.body.family?.seatLimit !== 6 || family.body.family?.seatsUsed !== 1) {
    throw new Error("Compiled account service did not create the expected Family Shield circle.");
  }

  const forbidden = await request("/v1/auth/challenge", {
    accountId,
    deviceId,
    operation: "snapshot",
    subject: "raw email content must be rejected",
  }, { expect: 400 });
  if (!String(forbidden.body.error || "").includes("rejects mailbox field subject")) {
    throw new Error("Account service mailbox-field firewall did not reject raw subject data.");
  }

  console.log(`Compiled account/Family Shield service smoke passed at ${baseUrl}.`);
  console.log("Signed registration, device-signed authentication, Family entitlement, family creation, and raw-mail rejection passed.");
} finally {
  await new Promise((resolve) => server.close(() => resolve()));
}
