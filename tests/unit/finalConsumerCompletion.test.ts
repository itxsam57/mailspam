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
import { InMemoryConsumerStateRepository } from "../../server/src/api/consumerStatePersistence.js";

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
    const composition = readFileSync(new URL("../../server/src/api/dashboardScripts.ts", import.meta.url), "utf8");

    expect(composition).toContain('"/consumer-product.js"');
    expect(source).toContain("Continue with Google");
    expect(source).toContain("Continue with Microsoft");
    expect(source).toContain("Add iCloud Mail");
    expect(source).toContain("Add Yahoo Mail");
    expect(source).toContain("developer");
    expect(source).toContain("/api/consumer/v1/accounts/");
    expect(source).toContain("Check Inbox & Mailbox Health");
    expect(source).toContain("Protection Activity");
    expect(source).toContain("Family Guardian");
    expect(source).not.toContain("localStorage");
    expect(source).not.toContain("sessionStorage");
    expect(source).not.toContain("refreshToken");
    expect(source).not.toContain("accessToken");
    expect(source).not.toContain("appPassword:");
  });
});
