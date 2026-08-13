import type {
  BillingEntitlementPolicy,
  BillingStore,
  BillingVerifierPort,
} from "./billingVerification.js";
import { HttpBillingVerifier } from "./billingVerification.js";
import type { EmailShieldPlan } from "../platform/accountFamilyTypes.js";

const DEFAULT_OFFLINE_CACHE_MS = 72 * 60 * 60 * 1_000;
const DEFAULT_GRACE_MS = 16 * 24 * 60 * 60 * 1_000;
const MAX_PRODUCT_IDS_PER_PLAN = 32;
const PRODUCT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;

function parseProductIds(value: string | undefined, label: string): Set<string> {
  const result = new Set<string>();
  for (const raw of value?.split(",") ?? []) {
    const id = raw.trim();
    if (!id) continue;
    if (!PRODUCT_ID_PATTERN.test(id)) throw new Error(`${label} contains an invalid billing product ID.`);
    result.add(id);
  }
  if (result.size > MAX_PRODUCT_IDS_PER_PLAN) throw new Error(`${label} contains too many billing product IDs.`);
  return result;
}

export interface BillingRuntimeConfiguration {
  enabled: boolean;
  verifiers: ReadonlyMap<BillingStore, BillingVerifierPort>;
  policy: BillingEntitlementPolicy;
  productCounts: { individual: number; family: number };
}

export function billingRuntimeConfigurationFromEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): BillingRuntimeConfiguration {
  const enabled = environment.EMAIL_SHIELD_PAID_PLANS_ENABLED === "1";
  const individual = parseProductIds(
    environment.EMAIL_SHIELD_BILLING_INDIVIDUAL_PRODUCT_IDS,
    "EMAIL_SHIELD_BILLING_INDIVIDUAL_PRODUCT_IDS",
  );
  const family = parseProductIds(
    environment.EMAIL_SHIELD_BILLING_FAMILY_PRODUCT_IDS,
    "EMAIL_SHIELD_BILLING_FAMILY_PRODUCT_IDS",
  );
  for (const id of individual) {
    if (family.has(id)) throw new Error("A billing product ID cannot map to both Individual and Family plans.");
  }

  const policy: BillingEntitlementPolicy = {
    productPlan(productId: string): { plan: EmailShieldPlan; seatLimit: number } | null {
      if (individual.has(productId)) return { plan: "individual", seatLimit: 1 };
      if (family.has(productId)) return { plan: "family", seatLimit: 6 };
      return null;
    },
    maximumOfflineCacheAgeMs: DEFAULT_OFFLINE_CACHE_MS,
    maximumGraceMs: DEFAULT_GRACE_MS,
  };

  const endpoint = environment.EMAIL_SHIELD_BILLING_VERIFIER_URL?.trim() ?? "";
  const token = environment.EMAIL_SHIELD_BILLING_VERIFIER_TOKEN?.trim() ?? "";
  const verifiers = new Map<BillingStore, BillingVerifierPort>();
  if (endpoint || token) {
    if (!endpoint || token.length < 32) {
      throw new Error("Billing verifier URL and a service token of at least 32 characters must be configured together.");
    }
    for (const store of ["apple", "google", "web"] as const) {
      verifiers.set(store, new HttpBillingVerifier(store, endpoint, token));
    }
  }

  if (enabled) {
    if (!endpoint || token.length < 32 || verifiers.size !== 3) {
      throw new Error("Paid plans are enabled but the server-side billing verifier is not fully configured.");
    }
    if (individual.size === 0 || family.size === 0) {
      throw new Error("Paid plans are enabled but exact Individual and Family product-ID allowlists are not configured.");
    }
  }

  return {
    enabled,
    verifiers,
    policy,
    productCounts: { individual: individual.size, family: family.size },
  };
}
