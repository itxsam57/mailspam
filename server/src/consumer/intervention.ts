import {
  extractStructuralScamFacts,
  type PaymentInstrument,
  type StructuralScamFacts,
} from "../engine/structuralScamEvidence.js";
import { classifyScamRiskCategories, type ScamRiskCategory } from "./familyGuardian.js";

const PHONE_PATTERN = /(?<!\d)(?:\+?\d[\d .()\-]{6,}\d)(?!\d)/g;
const REMOTE_TOOLS = ["anydesk", "teamviewer", "quick assist", "rustdesk", "screenconnect", "remote desktop", "ultraviewer", "zoho assist"] as const;
const PAYMENT_LABELS: Partial<Record<PaymentInstrument, string>> = {
  bank_transfer: "bank transfer",
  card: "card",
  crypto: "cryptocurrency",
  gift_card: "gift card",
  cash_app: "cash/payment app",
  unknown_money: "money transfer",
};
const HIGH_FRICTION_PAYMENT = new Set<PaymentInstrument>([
  "bank_transfer",
  "crypto",
  "gift_card",
  "cash_app",
]);
const FINANCIAL_OR_ACCOUNT_EVENTS = new Set<StructuralScamFacts["events"][number]>([
  "invoice",
  "payment",
  "purchase",
  "refund",
  "login",
  "account_restriction",
  "support_incident",
]);

function normalizePhone(value: string): string | null {
  const trimmed = value.trim();
  const plus = trimmed.startsWith("+");
  const digits = trimmed.replace(/\D/g, "");
  if (digits.length < 7 || digits.length > 15) return null;
  return `${plus ? "+" : ""}${digits}`;
}

function hasAny<T>(values: readonly T[], candidates: ReadonlySet<T>): boolean {
  return values.some((value) => candidates.has(value));
}

function paymentRequested(facts: StructuralScamFacts): boolean {
  return facts.requestedActions.includes("pay")
    || facts.requestedActions.includes("move_money")
    || facts.requestedActions.includes("send_gift_card_code");
}

function requestedPaymentMethods(facts: StructuralScamFacts): string[] {
  if (!paymentRequested(facts)) return [];
  const methods = facts.paymentInstruments
    .map((instrument) => PAYMENT_LABELS[instrument])
    .filter((value): value is string => Boolean(value));
  return [...new Set(methods)];
}

function hasFinancialOrAccountContext(facts: StructuralScamFacts): boolean {
  return hasAny(facts.events, FINANCIAL_OR_ACCOUNT_EVENTS);
}

function hasIrreversiblePaymentPressure(facts: StructuralScamFacts): boolean {
  const transferRequested = facts.requestedActions.includes("pay") || facts.requestedActions.includes("move_money");
  const highFriction = hasAny(facts.paymentInstruments, HIGH_FRICTION_PAYMENT);
  const pressure = facts.pressure.includes("urgent")
    || facts.pressure.includes("deadline")
    || facts.pressure.includes("irreversible");
  return transferRequested && highFriction && pressure;
}

export interface InterventionSignal {
  code: string;
  severity: "notice" | "warning" | "critical";
  title: string;
  detail: string;
}

export interface ScamInterventionAssessment {
  schemaVersion: 1;
  categories: ScamRiskCategory[];
  phoneNumbers: string[];
  remoteAccessTools: string[];
  requestedPaymentMethods: string[];
  signals: InterventionSignal[];
  recommendedAction: string;
  officialVerificationRequired: boolean;
}

export function assessScamIntervention(text: string): ScamInterventionAssessment {
  const bounded = String(text ?? "").slice(0, 32_000);
  const categories = classifyScamRiskCategories(bounded);
  const facts = extractStructuralScamFacts({ text: bounded });
  const phoneNumbers = [...new Set((bounded.match(PHONE_PATTERN) ?? []).map(normalizePhone).filter((value): value is string => Boolean(value)))].slice(0, 10);
  const lower = bounded.toLowerCase();
  const remoteAccessTools = REMOTE_TOOLS.filter((tool) => lower.includes(tool));
  const paymentMethods = requestedPaymentMethods(facts);
  const signals: InterventionSignal[] = [];

  if (phoneNumbers.length
    && facts.requestedActions.includes("call")
    && hasFinancialOrAccountContext(facts)) {
    signals.push({
      code: "CALLBACK_NUMBER_IN_SUSPICIOUS_CONTEXT",
      severity: "warning",
      title: "Do not verify using this phone number",
      detail: "The suspicious content supplies a callback number in a financial, account, or support context. Obtain the organization's contact details independently from its official app, statement, card or website instead.",
    });
  }

  if (facts.requestedActions.includes("send_gift_card_code")) {
    signals.push({
      code: "GIFT_CARD_CODE_EXFILTRATION",
      severity: "critical",
      title: "Gift-card value is being requested",
      detail: "The request asks you to transmit gift-card or voucher codes, numbers, or photos. Treat those codes like cash and do not send them to someone who contacted you unexpectedly.",
    });
  }

  if (facts.requestedActions.includes("send_otp") || facts.requestedActions.includes("send_recovery_secret")) {
    signals.push({
      code: "ACCOUNT_ACCESS_SECRET_REQUEST",
      severity: "critical",
      title: "Account-access secret requested",
      detail: "Never give a password, one-time code, recovery code, seed phrase, private key, or backup code to someone who contacted you unexpectedly.",
    });
  }

  if (facts.requestedActions.includes("install_remote_access")) {
    const financialContext = hasFinancialOrAccountContext(facts);
    signals.push({
      code: "REMOTE_ACCESS_REQUEST",
      severity: financialContext ? "critical" : "warning",
      title: "Remote-access software requested",
      detail: remoteAccessTools.length
        ? `The request asks you to install or grant remote control using ${remoteAccessTools.join(", ")}. Do not grant device access to an unexpected caller or message${financialContext ? " during a banking, refund, payment, or account-security interaction" : ""}.`
        : `The request asks you to install or grant remote device control. Do not grant device access to an unexpected caller or message${financialContext ? " during a banking, refund, payment, or account-security interaction" : ""}.`,
    });
  }

  if (hasIrreversiblePaymentPressure(facts)) {
    signals.push({
      code: "URGENT_IRREVERSIBLE_PAYMENT_REQUEST",
      severity: "critical",
      title: "High-risk payment pressure",
      detail: paymentMethods.length
        ? `The request combines time/irreversibility pressure with ${paymentMethods.join(", ")}. Stop before paying and verify through an independently obtained official channel.`
        : "The request combines time or irreversibility pressure with a high-friction value transfer. Stop before paying and verify through an independently obtained official channel.",
    });
  }

  return {
    schemaVersion: 1,
    categories,
    phoneNumbers,
    remoteAccessTools: [...remoteAccessTools],
    requestedPaymentMethods: paymentMethods,
    signals,
    recommendedAction: signals.some((signal) => signal.severity === "critical")
      ? "Stop the interaction. Do not pay, share codes, install remote-access software or use supplied contact details. Independently contact the claimed organization."
      : signals.length
        ? "Pause and independently verify the request before calling, paying or granting device/account access."
        : "No strong callback/payment/remote-access intervention signal was observed in this text; continue normal scam verification for sensitive actions.",
    officialVerificationRequired: signals.length > 0,
  };
}

export interface OfficialChannelResult {
  organization: string;
  officialWebsite: string;
  officialPhone: string | null;
  source: string;
}

export interface OfficialChannelDirectoryPort {
  lookup(organization: string, signal: AbortSignal): Promise<OfficialChannelResult | null>;
}

export class UnconfiguredOfficialChannelDirectory implements OfficialChannelDirectoryPort {
  async lookup(_organization: string, signal: AbortSignal): Promise<OfficialChannelResult | null> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    return null;
  }
}
