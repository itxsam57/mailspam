import { evaluateConsumerScamCheck, type ConsumerScamCheckDependencies, type ConsumerScamCheckResponseV1 } from "./scamCheck.js";
import { assessScamIntervention, type ScamInterventionAssessment } from "./intervention.js";

export interface ShoppingSafetyInputV1 {
  schemaVersion: 1;
  url: string;
  pageText?: string;
  sellerName?: string;
  advertisedPriceText?: string;
  paymentText?: string;
}

export interface ShoppingSafetySignal {
  code: string;
  severity: "notice" | "warning" | "critical";
  detail: string;
}

export interface ShoppingSafetyResultV1 {
  schemaVersion: 1;
  verdict: "no_strong_signal" | "caution" | "high_risk" | "unknown";
  destination: ConsumerScamCheckResponseV1;
  intervention: ScamInterventionAssessment;
  signals: ShoppingSafetySignal[];
  limitations: string[];
  privacy: "explicit_storefront_input_only";
}

function bounded(value: unknown, max: number): string {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string" || value.length > max) throw new Error("Shopping Safety input exceeds its local bound.");
  return value.trim();
}

export function analyzeShoppingSafety(
  input: ShoppingSafetyInputV1,
  dependencies: ConsumerScamCheckDependencies = {},
): ShoppingSafetyResultV1 {
  if (!input || input.schemaVersion !== 1) throw new Error("Shopping Safety input is invalid.");
  const url = bounded(input.url, 8_192);
  const parsed = new URL(url);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new Error("Shopping Safety accepts HTTP(S) storefronts only.");
  const pageText = bounded(input.pageText, 32_000);
  const sellerName = bounded(input.sellerName, 512);
  const advertisedPriceText = bounded(input.advertisedPriceText, 1_024);
  const paymentText = bounded(input.paymentText, 8_000);
  const combined = `${sellerName}\n${pageText}\n${advertisedPriceText}\n${paymentText}`.slice(0, 40_000);
  const destination = evaluateConsumerScamCheck({ schemaVersion: 1, kind: "url", url: parsed.toString() }, dependencies);
  const intervention = assessScamIntervention(combined);
  const signals: ShoppingSafetySignal[] = [];

  if (/\b(bank transfer|wire transfer|crypto|bitcoin|usdt|gift\s*card|friends\s*(?:and|&)\s*family)\b/i.test(paymentText || pageText)) {
    signals.push({
      code: "SHOPPING_IRREVERSIBLE_PAYMENT",
      severity: "critical",
      detail: "The seller requests a payment method with weak buyer protection or difficult recovery. Prefer a payment method with independent dispute protection.",
    });
  }
  if (/\b(only today|act now|last chance|few minutes|order immediately|before it is gone)\b/i.test(combined)) {
    signals.push({
      code: "SHOPPING_URGENCY_PRESSURE",
      severity: "warning",
      detail: "The storefront uses strong urgency pressure. Time pressure should not replace independent verification of the seller and payment destination.",
    });
  }
  if (/\b(contact us|support)\b/i.test(pageText) && /\b(?:gmail|yahoo|outlook|hotmail)\.com\b/i.test(pageText)) {
    signals.push({
      code: "SHOPPING_FREE_MAIL_SUPPORT_IDENTITY",
      severity: "warning",
      detail: "The storefront appears to use a consumer free-mail address for support. This is not proof of fraud, but it weakens identity consistency for an unfamiliar merchant.",
    });
  }
  if (/\b(?:whatsapp|telegram)\b/i.test(pageText) && /\b(pay|payment|order|deposit|advance)\b/i.test(combined)) {
    signals.push({
      code: "SHOPPING_OFF_PLATFORM_PAYMENT_CONTACT",
      severity: "warning",
      detail: "The seller moves payment/order handling to an off-platform messenger. Verify the business independently before sending money or identity documents.",
    });
  }
  if (destination.verdict === "confirmed_threat" || destination.verdict === "high_risk") {
    signals.push({
      code: "SHOPPING_DESTINATION_RISK",
      severity: destination.verdict === "confirmed_threat" ? "critical" : "warning",
      detail: "The storefront destination itself triggered Email Shield URL/domain risk evidence.",
    });
  }

  const critical = signals.some((signal) => signal.severity === "critical") || intervention.signals.some((signal) => signal.severity === "critical");
  const warning = signals.some((signal) => signal.severity === "warning") || intervention.signals.length > 0;
  const unknown = destination.verdict === "unknown";
  return {
    schemaVersion: 1,
    verdict: critical ? "high_risk" : warning ? "caution" : unknown ? "unknown" : "no_strong_signal",
    destination,
    intervention,
    signals,
    limitations: [
      "Shopping Safety evaluates only observable content and Email Shield destination evidence. It does not invent merchant age, review reputation, legal registration, inventory, price fairness or delivery history without an authoritative external source.",
      "A no-strong-signal result is not a guarantee that an unfamiliar seller is legitimate. Use payment methods with buyer protection and independently verify high-value purchases.",
    ],
    privacy: "explicit_storefront_input_only",
  };
}
