import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import {
  BillingEntitlementCoordinator,
  billingEventFingerprint,
  type BillingEvidence,
  type BillingVerifierPort,
  type VerifiedBillingEvent,
} from "../../server/src/billing/billingVerification.js";
import { FileBillingEventLedger } from "../../server/src/billing/billingEventLedger.js";
import { billingRuntimeConfigurationFromEnvironment } from "../../server/src/billing/billingRuntimeConfig.js";
import { InMemoryConsumerStateRepository } from "../../server/src/api/consumerStatePersistence.js";
import {
  defaultFamilyGuardianPreferences,
  familyGuardianPreferenceKey,
  FileFamilyGuardianPreferencesRepository,
} from "../../server/src/consumer/familyGuardianPreferences.js";

describe("final consumer completion contracts", () => {
  it("persists billing idempotency across coordinator restart without storing receipt payloads", async () => {
    const directory = mkdtempSync(join(tmpdir(), "email-shield-billing-ledger-"));
    try {
      const file = join(directory, "billing-events.json");
      const now = Date.parse("2026-08-13T00:00:00.000Z");
      const evidence: BillingEvidence = {
        store: "google",
        eventId: "evt-001",
        eventType: "purchase",
        productId: "email-shield-family-monthly",
        storeAccountReference: "store-account-ref",
        purchaseReference: "purchase-ref",
        occurredAt: now - 1_000,
        expiresAt: now + 30 * 24 * 60 * 60 * 1_000,
        graceUntil: null,
        originalPurchaseReference: null,
        familyTransferFromAccountReference: null,
        verificationPayload: "opaque-receipt-secret-that-must-not-be-persisted",
      };
      const verified: VerifiedBillingEvent = {
        store: "google",
        eventId: evidence.eventId,
        eventType: evidence.eventType,
        plan: "family",
        productId: evidence.productId,
        storeAccountReference: evidence.storeAccountReference,
        purchaseReference: evidence.purchaseReference,
        occurredAt: evidence.occurredAt,
        expiresAt: evidence.expiresAt,
        graceUntil: null,
        originalPurchaseReference: null,
        familyTransferFromAccountReference: null,
        verifiedBy: "test-store-verifier",
      };
      let verificationCalls = 0;
      const verifier: BillingVerifierPort = {
        store: "google",
        async verify() {
          verificationCalls += 1;
          return structuredClone(verified);
        },
      };
      let applied = 0;
      const first = new BillingEntitlementCoordinator(
        new Map([["google", verifier]]),
        new FileBillingEventLedger(file),
        () => { applied += 1; },
      );
      const initial = await first.process("acct_test", evidence, new AbortController().signal);
      expect(initial.duplicate).toBe(false);
      expect(applied).toBe(1);

      const fingerprint = billingEventFingerprint(verified);
      expect(new FileBillingEventLedger(file).has(fingerprint)).toBe(true);
      const persisted = readFileSync(file, "utf8");
      expect(persisted).toContain(fingerprint);
      expect(persisted).not.toContain(evidence.verificationPayload);
      expect(persisted).not.toContain(evidence.purchaseReference);
      expect(persisted).not.toContain(evidence.storeAccountReference);

      const restarted = new BillingEntitlementCoordinator(
        new Map([["google", verifier]]),
        new FileBillingEventLedger(file),
        () => { applied += 1; },
      );
      const replay = await restarted.process("acct_test", evidence, new AbortController().signal);
      expect(replay.duplicate).toBe(true);
      expect(applied).toBe(1);
      expect(verificationCalls).toBe(2);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("keeps paid plans free-only by default and requires exact configured SKUs when enabled", () => {
    const disabled = billingRuntimeConfigurationFromEnvironment({});
    expect(disabled.enabled).toBe(false);
    expect(disabled.verifiers.size).toBe(0);
    expect(disabled.policy.productPlan("anything-family-looking")).toBeNull();

    expect(() => billingRuntimeConfigurationFromEnvironment({
      EMAIL_SHIELD_PAID_PLANS_ENABLED: "1",
    })).toThrow(/verifier/i);

    const enabled = billingRuntimeConfigurationFromEnvironment({
      EMAIL_SHIELD_PAID_PLANS_ENABLED: "1",
      EMAIL_SHIELD_BILLING_VERIFIER_URL: "https://billing.example.test",
      EMAIL_SHIELD_BILLING_VERIFIER_TOKEN: "t".repeat(48),
      EMAIL_SHIELD_BILLING_INDIVIDUAL_PRODUCT_IDS: "com.emailshield.individual.monthly",
      EMAIL_SHIELD_BILLING_FAMILY_PRODUCT_IDS: "com.emailshield.family.monthly",
    });
    expect(enabled.enabled).toBe(true);
    expect(enabled.verifiers.size).toBe(3);
    expect(enabled.policy.productPlan("com.emailshield.individual.monthly")).toEqual({ plan: "individual", seatLimit: 1 });
    expect(enabled.policy.productPlan("com.emailshield.family.monthly")).toEqual({ plan: "family", seatLimit: 6 });
    expect(enabled.policy.productPlan("com.fake.family.monthly")).toBeNull();
  });

  it("stores Family Guardian preferences under a hashed account key and keeps high-risk mode opt-in", () => {
    const directory = mkdtempSync(join(tmpdir(), "email-shield-family-guardian-"));
    try {
      const file = join(directory, "preferences.json");
      const accountId = "acct_private-family-owner";
      const repository = new FileFamilyGuardianPreferencesRepository(file);
      expect(repository.load(accountId).highRiskMemberMode).toBe(false);

      const preferences = defaultFamilyGuardianPreferences();
      preferences.highRiskMemberMode = true;
      preferences.notificationsPaused = true;
      preferences.categories.banking = "all";
      repository.save(accountId, preferences);

      const restored = new FileFamilyGuardianPreferencesRepository(file).load(accountId);
      expect(restored.highRiskMemberMode).toBe(true);
      expect(restored.notificationsPaused).toBe(true);
      expect(restored.categories.banking).toBe("all");

      const raw = readFileSync(file, "utf8");
      expect(raw).toContain(familyGuardianPreferenceKey(accountId));
      expect(raw).not.toContain(accountId);
      expect(raw).not.toMatch(/mailbox|subject|messageId|senderAddress|refreshToken|appPassword/i);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("never exposes reversible provider message IDs through public Activity", () => {
    const repository = new InMemoryConsumerStateRepository();
    const accountKey = "a".repeat(64);
    const providerNativeId = "private-provider-message-id";
    const activity = repository.appendActivity(accountKey, {
      kind: "quarantined",
      severity: "attention",
      provider: "gmail",
      title: "Message moved to Spam/Junk",
      detail: "A provider action completed.",
      reasonCodes: ["USER_MOVE_TO_SPAM"],
      undo: {
        providerNativeIds: [providerNativeId],
        expiresAt: Date.now() + 60_000,
        usedAt: null,
      },
    });

    const publicJson = JSON.stringify(repository.listActivity(accountKey));
    expect(publicJson).not.toContain(providerNativeId);
    expect(repository.listActivity(accountKey)[0]?.undoAvailable).toBe(true);
    expect(repository.getActivity(accountKey, activity.activityId)?.undo?.providerNativeIds).toEqual([providerNativeId]);

    repository.markActivityUndone(accountKey, activity.activityId);
    expect(repository.listActivity(accountKey)[0]?.undoAvailable).toBe(false);
    expect(repository.listActivity(accountKey)[0]?.undone).toBe(true);
  });

  it("keeps the normal consumer shell on provider sign-in cards and out of browser secret storage", () => {
    const source = readFileSync(new URL("../../web/consumer-product.js", import.meta.url), "utf8");
    const billing = readFileSync(new URL("../../web/billing-plan-ui.js", import.meta.url), "utf8");
    const guardian = readFileSync(new URL("../../web/family-guardian-preferences.js", import.meta.url), "utf8");
    const composition = readFileSync(new URL("../../server/src/api/dashboardScripts.ts", import.meta.url), "utf8");

    expect(composition).toContain('"/consumer-product.js"');
    expect(composition).toContain('"/billing-plan-ui.js"');
    expect(composition).toContain('"/family-guardian-preferences.js"');
    expect(source).toContain("Continue with Google");
    expect(source).toContain("Continue with Microsoft");
    expect(source).toContain("Add iCloud Mail");
    expect(source).toContain("Add Yahoo Mail");
    expect(source).toContain("developer");
    expect(source).toContain("/api/consumer/v1/accounts/");
    expect(source).toContain("Check Inbox & Mailbox Health");
    expect(source).toContain("Protection Activity");
    expect(source).toContain("Family Guardian");
    expect(billing).toContain("emailShieldBillingBridge");
    expect(billing).toContain("server-verified Email Shield entitlement");
    expect(guardian).toContain("High-risk-member mode");
    for (const browserSource of [source, billing, guardian]) {
      expect(browserSource).not.toContain("localStorage");
      expect(browserSource).not.toContain("sessionStorage");
      expect(browserSource).not.toContain("refreshToken");
      expect(browserSource).not.toContain("accessToken");
      expect(browserSource).not.toContain("appPassword:");
    }
  });

  it("binds account-scoped consumer reads, renders, Undo and cleanup to the mailbox that produced them", () => {
    const source = readFileSync(new URL("../../web/consumer-product.js", import.meta.url), "utf8");

    expect(source).toContain("healthAccountId: null");
    expect(source).toContain("function bindSelectedAccount(id)");
    expect(source).toContain("function stillSelected(id)");
    expect(source).toContain("state.accountId === id && activeMailboxId() === id");
    expect(source).toContain("clearAccountScopedViews()");
    expect(source).toContain("if (!stillSelected(id)) return");
    expect(source).toContain("function renderHealth(result, accountId)");
    expect(source).toContain("if (!stillSelected(accountId)) return");
    expect(source).toContain("state.healthAccountId = accountId");
    expect(source).toContain("/api/consumer/v1/accounts/${encodeURIComponent(accountId)}/cleanup");
    expect(source).toContain("Mailbox selection changed. Run Health again before cleaning mail.");
    expect(source).toContain("if(!stillSelected(id)){document.getElementById('consumerActivityStatus').textContent='Mailbox selection changed. Refresh Activity before using Undo.'");
    expect(source).toContain("state.healthAccountId===id");
    expect(source).not.toContain("|| state.accountId");
    expect(source).not.toContain("const id=selectedSessionOrThrow();if(!confirm(`Move older matching mail");
  });
});