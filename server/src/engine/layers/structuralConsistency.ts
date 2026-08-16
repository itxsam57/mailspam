import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import { extractStructuralScamFacts, type StructuralScamFacts } from "../structuralScamEvidence.js";
import type { Evidence, LayerResult } from "../verdict.js";
import { identityImpersonationLayer } from "./identityImpersonation.js";

export type StructuralEvidenceCode =
  | "IMPERSONATED_TRANSACTION_ORIGIN"
  | "GIFT_CARD_CODE_EXFILTRATION"
  | "ACCOUNT_SECRET_EXFILTRATION"
  | "IRREVERSIBLE_PAYMENT_PRESSURE"
  | "REMOTE_ACCESS_FINANCIAL_PRESSURE"
  | "SECRECY_PAYMENT_DIVERSION";

interface StructuralContext {
  facts: StructuralScamFacts;
  identity: LayerResult;
}

interface StructuralRule {
  code: StructuralEvidenceCode;
  score: number | ((context: StructuralContext) => number);
  description: string;
  matches(context: StructuralContext): boolean;
}

const TRANSACTION_EVENTS = new Set<StructuralScamFacts["events"][number]>([
  "invoice",
  "payment",
  "purchase",
  "refund",
  "subscription",
  "account_restriction",
]);
const FINANCIAL_REMOTE_CONTEXT = new Set<StructuralScamFacts["events"][number]>([
  "payment",
  "purchase",
  "refund",
  "account_restriction",
  "support_incident",
]);
const HIGH_FRICTION_INSTRUMENTS = new Set<StructuralScamFacts["paymentInstruments"][number]>([
  "bank_transfer",
  "crypto",
  "gift_card",
  "cash_app",
]);
const IDENTITY_CONTRADICTIONS = new Set([
  "BRAND_DOMAIN_MISMATCH",
  "BRAND_LOOKALIKE_DOMAIN",
  "EXPLICIT_DOMAIN_CLAIM_MISMATCH",
  "REPLY_TO_MISMATCH",
]);

function has<T>(values: readonly T[], candidates: ReadonlySet<T>): boolean {
  return values.some((value) => candidates.has(value));
}

function hasIdentityContradiction(context: StructuralContext): boolean {
  return context.identity.evidence.some((item) => IDENTITY_CONTRADICTIONS.has(item.code));
}

function hasValueTransfer(context: StructuralContext): boolean {
  const { facts } = context;
  const requestedTransfer = facts.requestedActions.includes("pay")
    || facts.requestedActions.includes("move_money")
    || facts.requestedActions.includes("send_gift_card_code");
  const instrument = has(facts.paymentInstruments, HIGH_FRICTION_INSTRUMENTS)
    || facts.paymentInstruments.includes("unknown_money");
  return requestedTransfer && instrument;
}

function irreversiblePaymentPressureScore(context: StructuralContext): number {
  const hasDeadline = context.facts.pressure.includes("deadline");
  const explicitlyIrreversible = context.facts.pressure.includes("irreversible");
  // A real value-transfer request plus both an explicit deadline and explicit
  // irreversibility is a stronger single compound fact than either pressure
  // signal alone. Keep it in one evidence item so the same topology is never
  // counted again by a legacy phrase rule merely to cross High Risk.
  return hasDeadline && explicitlyIrreversible ? 6 : 4;
}

/**
 * One fixed table owns provider-neutral structural scam scores. Provider
 * placement, adapter identity and consumer surface are intentionally absent.
 */
const STRUCTURAL_RULES: readonly StructuralRule[] = [
  {
    code: "IMPERSONATED_TRANSACTION_ORIGIN",
    score: (context) => context.identity.evidence.some((item) => item.code === "REPLY_TO_MISMATCH") ? 4 : 3,
    description: "A transactional or account claim conflicts with independently observed sender identity evidence.",
    matches: (context) => context.facts.organizationClaims.length > 0
      && has(context.facts.events, TRANSACTION_EVENTS)
      && hasIdentityContradiction(context),
  },
  {
    code: "GIFT_CARD_CODE_EXFILTRATION",
    score: 4,
    description: "The message asks for gift-card or voucher value and requests transmission of the redeemable code or number.",
    matches: (context) => context.facts.paymentInstruments.includes("gift_card")
      && context.facts.requestedActions.includes("send_gift_card_code"),
  },
  {
    code: "ACCOUNT_SECRET_EXFILTRATION",
    score: 4,
    description: "The message asks the recipient to transmit an account-access secret such as an OTP, passcode, password, or recovery secret.",
    matches: (context) => context.facts.requestedActions.includes("send_otp")
      || context.facts.requestedActions.includes("send_recovery_secret"),
  },
  {
    code: "IRREVERSIBLE_PAYMENT_PRESSURE",
    score: irreversiblePaymentPressureScore,
    description: "A high-friction value-transfer request is combined with urgency, a deadline, or explicit irreversibility.",
    matches: (context) => has(context.facts.paymentInstruments, HIGH_FRICTION_INSTRUMENTS)
      && (context.facts.requestedActions.includes("pay") || context.facts.requestedActions.includes("move_money"))
      && (context.facts.pressure.includes("urgent")
        || context.facts.pressure.includes("deadline")
        || context.facts.pressure.includes("irreversible")),
  },
  {
    code: "REMOTE_ACCESS_FINANCIAL_PRESSURE",
    score: 4,
    description: "The message requests remote-control software or device access in a payment, refund, account-security, or support context.",
    matches: (context) => context.facts.requestedActions.includes("install_remote_access")
      && has(context.facts.events, FINANCIAL_REMOTE_CONTEXT),
  },
  {
    code: "SECRECY_PAYMENT_DIVERSION",
    score: 3,
    description: "A value-transfer request is paired with secrecy or an instruction not to verify the request independently.",
    matches: (context) => hasValueTransfer(context)
      && (context.facts.pressure.includes("secrecy") || context.facts.pressure.includes("no_independent_contact")),
  },
];

function contextFor(envelope: CanonicalEnvelope, identity?: LayerResult): StructuralContext {
  return {
    facts: extractStructuralScamFacts({
      subject: envelope.subject,
      text: envelope.textPreview,
      htmlText: envelope.htmlSignals?.extractedText ?? null,
      displayName: envelope.from.displayName,
      links: envelope.links,
    }),
    identity: identity ?? identityImpersonationLayer(envelope),
  };
}

function matchingRules(context: StructuralContext): StructuralRule[] {
  return STRUCTURAL_RULES.filter((rule) => rule.matches(context));
}

export function structuralConsistencyEvidenceCodes(
  envelope: CanonicalEnvelope,
  identity?: LayerResult,
): StructuralEvidenceCode[] {
  return matchingRules(contextFor(envelope, identity)).map((rule) => rule.code);
}

export function structuralConsistencyLayer(
  envelope: CanonicalEnvelope,
  identity?: LayerResult,
): LayerResult {
  const context = contextFor(envelope, identity);
  const evidence: Evidence[] = matchingRules(context).map((rule) => ({
    layer: "structural_consistency",
    code: rule.code,
    description: rule.description,
    scoreContribution: typeof rule.score === "function" ? rule.score(context) : rule.score,
    source: "local",
  }));

  return {
    layer: "structural_consistency",
    applicable: true,
    evidence,
    incomplete: false,
  };
}
