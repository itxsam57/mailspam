import { createHash } from "node:crypto";
import type { EmailShieldPlan, EntitlementSource, VerifiedEntitlement } from "../platform/accountFamilyTypes.js";

export type BillingStore = "apple" | "google" | "web";
export type BillingEventType = "purchase" | "renewal" | "grace" | "cancellation" | "expiration" | "revocation" | "restore" | "transfer";

const BILLING_EVENT_TYPES: readonly BillingEventType[] = Object.freeze([
  "purchase",
  "renewal",
  "grace",
  "cancellation",
  "expiration",
  "revocation",
  "restore",
  "transfer",
]);

const BILLING_EVIDENCE_FIELDS = new Set([
  "store",
  "eventId",
  "eventType",
  "productId",
  "storeAccountReference",
  "purchaseReference",
  "occurredAt",
  "expiresAt",
  "graceUntil",
  "originalPurchaseReference",
  "familyTransferFromAccountReference",
  "verificationPayload",
]);

export interface BillingEvidence {
  store: BillingStore;
  eventId: string;
  eventType: BillingEventType;
  productId: string;
  storeAccountReference: string;
  purchaseReference: string;
  occurredAt: number;
  expiresAt: number | null;
  graceUntil: number | null;
  originalPurchaseReference: string | null;
  familyTransferFromAccountReference: string | null;
  /** Opaque evidence is interpreted only by a store verifier; it is never returned to clients or persisted by the normalized entitlement ledger. */
  verificationPayload: string;
}

export interface VerifiedBillingEvent {
  store: BillingStore;
  eventId: string;
  eventType: BillingEventType;
  plan: EmailShieldPlan;
  productId: string;
  storeAccountReference: string;
  purchaseReference: string;
  occurredAt: number;
  expiresAt: number | null;
  graceUntil: number | null;
  originalPurchaseReference: string | null;
  familyTransferFromAccountReference: string | null;
  verifiedBy: string;
}

export interface BillingVerifierPort {
  readonly store: BillingStore;
  verify(evidence: BillingEvidence, signal: AbortSignal): Promise<VerifiedBillingEvent>;
}

export interface BillingEventLedger {
  has(eventFingerprint: string): boolean;
  record(eventFingerprint: string, accountId: string, verifiedAt: number): void;
}

export class InMemoryBillingEventLedger implements BillingEventLedger {
  private readonly events = new Map<string, { accountId: string; verifiedAt: number }>();
  has(eventFingerprint: string): boolean { return this.events.has(eventFingerprint); }
  record(eventFingerprint: string, accountId: string, verifiedAt: number): void { this.events.set(eventFingerprint, { accountId, verifiedAt }); }
}

export interface BillingEntitlementPolicy {
  productPlan(productId: string): { plan: EmailShieldPlan; seatLimit: number } | null;
  maximumOfflineCacheAgeMs: number;
  maximumGraceMs: number;
}

export const DEFAULT_BILLING_ENTITLEMENT_POLICY: BillingEntitlementPolicy = Object.freeze({
  productPlan(productId: string): { plan: EmailShieldPlan; seatLimit: number } | null {
    const normalized = productId.trim().toLowerCase();
    if (/\b(?:individual|premium|pro)\b/.test(normalized)) return { plan: "individual", seatLimit: 1 };
    if (/\bfamily\b/.test(normalized)) return { plan: "family", seatLimit: 6 };
    if (/\bfree\b/.test(normalized)) return { plan: "free", seatLimit: 1 };
    return null;
  },
  maximumOfflineCacheAgeMs: 72 * 60 * 60 * 1_000,
  maximumGraceMs: 16 * 24 * 60 * 60 * 1_000,
});

function strictText(value: unknown, label: string, max = 512): string {
  if (typeof value !== "string") throw new Error(`${label} is required.`);
  const normalized = value.trim();
  if (!normalized || normalized.length > max || /[\u0000-\u001f\u007f]/.test(normalized)) throw new Error(`${label} is invalid.`);
  return normalized;
}

function validTime(value: unknown, nullable = false): number | null {
  if (nullable && value === null) return null;
  if (!Number.isSafeInteger(value) || Number(value) <= 0) throw new Error("Billing timestamp is invalid.");
  return Number(value);
}

export function validateBillingEvidence(input: BillingEvidence): BillingEvidence {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Billing evidence is required.");
  const record = input as unknown as Record<string, unknown>;
  if (Object.keys(record).some((key) => !BILLING_EVIDENCE_FIELDS.has(key))) {
    throw new Error("Billing evidence contains unsupported fields.");
  }
  if (input.store !== "apple" && input.store !== "google" && input.store !== "web") throw new Error("Billing store is invalid.");
  if (!BILLING_EVENT_TYPES.includes(input.eventType)) throw new Error("Billing event type is invalid.");
  return {
    store: input.store,
    eventId: strictText(input.eventId, "Billing event ID", 256),
    eventType: input.eventType,
    productId: strictText(input.productId, "Billing product ID", 256),
    storeAccountReference: strictText(input.storeAccountReference, "Billing account reference", 512),
    purchaseReference: strictText(input.purchaseReference, "Purchase reference", 512),
    occurredAt: validTime(input.occurredAt)!,
    expiresAt: validTime(input.expiresAt, true),
    graceUntil: validTime(input.graceUntil, true),
    originalPurchaseReference: input.originalPurchaseReference === null ? null : strictText(input.originalPurchaseReference, "Original purchase reference", 512),
    familyTransferFromAccountReference: input.familyTransferFromAccountReference === null ? null : strictText(input.familyTransferFromAccountReference, "Family transfer source", 512),
    verificationPayload: strictText(input.verificationPayload, "Billing verification payload", 128 * 1024),
  };
}

export function billingEventFingerprint(event: Pick<VerifiedBillingEvent, "store" | "eventId" | "purchaseReference">): string {
  return createHash("sha256")
    .update(`email-shield-billing-event-v1\n${event.store}\n${event.eventId}\n${event.purchaseReference}`, "utf8")
    .digest("hex");
}

function source(store: BillingStore): EntitlementSource {
  return store === "apple" ? "apple" : store === "google" ? "google" : "web";
}

export function entitlementFromVerifiedBillingEvent(
  event: VerifiedBillingEvent,
  policy: BillingEntitlementPolicy = DEFAULT_BILLING_ENTITLEMENT_POLICY,
  now = Date.now(),
): VerifiedEntitlement {
  const mapped = policy.productPlan(event.productId);
  if (!mapped || mapped.plan !== event.plan) throw new Error("Verified billing product does not match Email Shield plan policy.");
  if (event.occurredAt > now + 10 * 60_000) throw new Error("Verified billing event timestamp is in the future.");
  const graceUntil = event.graceUntil === null
    ? null
    : Math.min(event.graceUntil, now + policy.maximumGraceMs);

  let status: VerifiedEntitlement["status"];
  if (event.eventType === "revocation") status = "revoked";
  else if (event.eventType === "expiration") status = "expired";
  else if (event.eventType === "grace") status = "grace";
  else if (event.eventType === "cancellation") {
    status = event.expiresAt !== null && event.expiresAt <= now ? "expired" : "active";
  } else status = "active";

  if (event.expiresAt !== null && event.expiresAt <= now && status === "active") {
    status = graceUntil !== null && graceUntil > now ? "grace" : "expired";
  }
  return {
    plan: mapped.plan,
    status,
    source: source(event.store),
    productId: event.productId,
    storeAccountReference: event.storeAccountReference,
    verifiedAt: now,
    expiresAt: event.expiresAt,
    graceUntil,
    seatLimit: mapped.seatLimit,
  };
}

export function entitlementCacheUsable(
  entitlement: VerifiedEntitlement,
  policy: BillingEntitlementPolicy = DEFAULT_BILLING_ENTITLEMENT_POLICY,
  now = Date.now(),
): { usable: boolean; reason: "fresh" | "grace" | "stale" | "expired" | "revoked" } {
  if (entitlement.status === "revoked") return { usable: false, reason: "revoked" };
  if (entitlement.status === "expired") return { usable: false, reason: "expired" };
  if (entitlement.expiresAt !== null && entitlement.expiresAt <= now) {
    if (entitlement.status === "grace" && entitlement.graceUntil !== null && entitlement.graceUntil > now) return { usable: true, reason: "grace" };
    return { usable: false, reason: "expired" };
  }
  if (now - entitlement.verifiedAt > policy.maximumOfflineCacheAgeMs && entitlement.source !== "development") {
    return { usable: false, reason: "stale" };
  }
  return { usable: true, reason: "fresh" };
}

export class BillingEntitlementCoordinator {
  constructor(
    private readonly verifiers: ReadonlyMap<BillingStore, BillingVerifierPort>,
    private readonly ledger: BillingEventLedger,
    private readonly applyEntitlement: (accountId: string, entitlement: VerifiedEntitlement) => void,
    private readonly policy: BillingEntitlementPolicy = DEFAULT_BILLING_ENTITLEMENT_POLICY,
  ) {}

  async process(accountId: string, rawEvidence: BillingEvidence, signal: AbortSignal): Promise<{ duplicate: boolean; entitlement: VerifiedEntitlement }> {
    const evidence = validateBillingEvidence(rawEvidence);
    const verifier = this.verifiers.get(evidence.store);
    if (!verifier || verifier.store !== evidence.store) throw new Error(`No ${evidence.store} billing verifier is configured.`);
    const verified = await verifier.verify(evidence, signal);
    if (
      verified.store !== evidence.store
      || verified.eventId !== evidence.eventId
      || verified.purchaseReference !== evidence.purchaseReference
      || verified.eventType !== evidence.eventType
      || verified.productId !== evidence.productId
      || verified.storeAccountReference !== evidence.storeAccountReference
    ) {
      throw new Error("Billing verifier returned evidence for a different transaction.");
    }
    strictText(verified.verifiedBy, "Billing verifier identity", 256);
    const fingerprint = billingEventFingerprint(verified);
    const entitlement = entitlementFromVerifiedBillingEvent(verified, this.policy);
    if (this.ledger.has(fingerprint)) return { duplicate: true, entitlement };
    this.applyEntitlement(accountId, entitlement);
    this.ledger.record(fingerprint, accountId, Date.now());
    return { duplicate: false, entitlement };
  }
}

/**
 * Server-side verifier gateway. Store credentials/signing keys remain behind
 * the gateway; apps submit store evidence to their own account service, never a
 * secret embedded verifier key.
 */
export class HttpBillingVerifier implements BillingVerifierPort {
  readonly store: BillingStore;
  private readonly endpoint: string;

  constructor(store: BillingStore, endpoint: string, private readonly serviceToken: string) {
    this.store = store;
    const parsed = new URL(endpoint);
    if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && ["127.0.0.1", "localhost", "::1"].includes(parsed.hostname))) {
      throw new Error("Billing verifier endpoint requires HTTPS except for loopback acceptance testing.");
    }
    if (serviceToken.length < 32) throw new Error("Billing verifier service token is too short.");
    this.endpoint = parsed.toString().replace(/\/$/, "");
  }

  async verify(evidence: BillingEvidence, signal: AbortSignal): Promise<VerifiedBillingEvent> {
    const timeout = AbortSignal.timeout(15_000);
    const composite = typeof AbortSignal.any === "function" ? AbortSignal.any([signal, timeout]) : signal;
    const response = await fetch(`${this.endpoint}/v1/verify/${this.store}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.serviceToken}`,
      },
      body: JSON.stringify(evidence),
      redirect: "error",
      cache: "no-store",
      signal: composite,
    });
    if (!response.ok) throw new Error(`${this.store} billing verifier returned HTTP ${response.status}.`);
    const raw = await response.text();
    if (Buffer.byteLength(raw, "utf8") > 64 * 1024) throw new Error("Billing verifier response is oversized.");
    const result = JSON.parse(raw) as VerifiedBillingEvent;
    if (!result || typeof result !== "object" || result.store !== this.store) throw new Error("Billing verifier response is invalid.");
    return result;
  }
}
