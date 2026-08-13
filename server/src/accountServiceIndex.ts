import { resolve } from "node:path";
import { mkdirSync } from "node:fs";
import express from "express";
import { accountServiceStoreFromEnvironment } from "./accountService/store.js";
import { SharedAccountFamilyService } from "./accountService/service.js";
import { createAccountLifecycleServer } from "./accountService/lifecycleServer.js";
import { createAccountBillingServer } from "./accountService/billingServer.js";
import { createAccountServiceServer } from "./accountService/server.js";
import { BillingEntitlementCoordinator } from "./billing/billingVerification.js";
import { FileBillingEventLedger } from "./billing/billingEventLedger.js";
import { billingRuntimeConfigurationFromEnvironment } from "./billing/billingRuntimeConfig.js";

const port = Number(process.env.PORT ?? 4175);
const host = process.env.HOST ?? "127.0.0.1";
if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("Account service PORT is invalid.");

const production = process.env.NODE_ENV === "production";
const dataDirectory = resolve(process.env.EMAIL_SHIELD_ACCOUNT_SERVICE_DATA_DIR?.trim() || ".email-shield-account-service");
mkdirSync(dataDirectory, { recursive: true, mode: 0o700 });
const store = accountServiceStoreFromEnvironment({
  dataDirectory,
  storageKeyBase64: process.env.EMAIL_SHIELD_ACCOUNT_SERVICE_STORAGE_KEY,
  production,
});
const service = new SharedAccountFamilyService(store);
const adminToken = process.env.EMAIL_SHIELD_ACCOUNT_SERVICE_ADMIN_TOKEN?.trim();
if (production && (!adminToken || adminToken.length < 32)) {
  throw new Error("EMAIL_SHIELD_ACCOUNT_SERVICE_ADMIN_TOKEN with at least 32 characters is required in production.");
}

const billing = billingRuntimeConfigurationFromEnvironment();
const billingLedger = new FileBillingEventLedger(resolve(dataDirectory, "billing-events-v1.json"));
let billingCoordinator: BillingEntitlementCoordinator | null = null;
if (billing.enabled) {
  billingLedger.assertReadable();
  billingCoordinator = new BillingEntitlementCoordinator(
    billing.verifiers,
    billingLedger,
    (accountId, entitlement) => { void service.applyVerifiedEntitlement(accountId, entitlement); },
    billing.policy,
  );
}

const trustProxy = process.env.EMAIL_SHIELD_ACCOUNT_SERVICE_TRUST_PROXY === "1";
const app = express();
// Lifecycle and billing are mounted before the original service because the
// original service owns its final 404. All three routers share one service/store
// and therefore one device-challenge authority and one encrypted account/family database.
app.use(createAccountLifecycleServer(service, store, { trustProxy }));
app.use(createAccountBillingServer(service, billingCoordinator, { enabled: billing.enabled, trustProxy }));
app.use(createAccountServiceServer(service, {
  adminToken,
  allowDevelopmentEntitlements: process.env.EMAIL_SHIELD_ACCOUNT_SERVICE_ALLOW_DEVELOPMENT_ENTITLEMENTS === "1",
  trustProxy,
}));

app.listen(port, host, () => {
  console.log(`Email Shield account/family service listening on http://${host}:${port}`);
  console.log(`Paid plans: ${billing.enabled ? `enabled (${billing.productCounts.individual} Individual SKU(s), ${billing.productCounts.family} Family SKU(s))` : "disabled (free-only kill switch)"}`);
});
