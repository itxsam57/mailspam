import { classifyScamRiskCategories, type ScamRiskCategory } from "./familyGuardian.js";

const PHONE_PATTERN = /(?<!\d)(?:\+?\d[\d .()\-]{6,}\d)(?!\d)/g;
const REMOTE_TOOLS = ["anydesk", "teamviewer", "quick assist", "rustdesk", "screenconnect", "remote desktop", "ultraviewer", "zoho assist"] as const;
const PAYMENT_PATTERNS: Array<[string, RegExp]> = [
  ["bank transfer", /\b(bank transfer|wire transfer|swift|iban|routing number)\b/i],
  ["cryptocurrency", /\b(crypto|bitcoin|ethereum|usdt|wallet|seed phrase)\b/i],
  ["gift card", /\b(gift\s*card|steam card|itunes card|google play card|voucher code)\b/i],
  ["cash/payment app", /\b(zelle|cash app|venmo|paypal friends|payment app)\b/i],
];

function normalizePhone(value: string): string | null {
  const trimmed = value.trim();
  const plus = trimmed.startsWith("+");
  const digits = trimmed.replace(/\D/g, "");
  if (digits.length < 7 || digits.length > 15) return null;
  return `${plus ? "+" : ""}${digits}`;
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
  const phoneNumbers = [...new Set((bounded.match(PHONE_PATTERN) ?? []).map(normalizePhone).filter((value): value is string => Boolean(value)))].slice(0, 10);
  const remoteAccessTools = REMOTE_TOOLS.filter((tool) => bounded.toLowerCase().includes(tool));
  const requestedPaymentMethods = PAYMENT_PATTERNS.filter(([, pattern]) => pattern.test(bounded)).map(([name]) => name);
  const signals: InterventionSignal[] = [];

  if (phoneNumbers.length && /\b(call|phone|hotline|support|refund|fraud department|security department)\b/i.test(bounded)) {
    signals.push({
      code: "CALLBACK_NUMBER_IN_SUSPICIOUS_CONTEXT",
      severity: "warning",
      title: "Do not verify using this phone number",
      detail: "The suspicious content supplies a callback number. Obtain the organization's contact details independently from its official app, statement, card or website instead.",
    });
  }
  if (remoteAccessTools.length) {
    signals.push({
      code: "REMOTE_ACCESS_REQUEST",
      severity: requestedPaymentMethods.length ? "critical" : "warning",
      title: "Remote-access software requested",
      detail: `The content mentions ${remoteAccessTools.join(", ")}. Do not install or open remote-control software at the request of an unexpected caller/message, especially during refunds, banking or payments.`,
    });
  }
  if (requestedPaymentMethods.length && /\b(urgent|immediately|today|now|avoid arrest|account closed|refund|release|unlock|fee)\b/i.test(bounded)) {
    signals.push({
      code: "URGENT_IRREVERSIBLE_PAYMENT_REQUEST",
      severity: "critical",
      title: "High-risk payment pressure",
      detail: `The request combines urgency with ${requestedPaymentMethods.join(", ")}. Stop before paying and verify through an independently obtained official channel.`,
    });
  }
  if (categories.includes("account_takeover") && /\b(code|otp|password|recovery|login)\b/i.test(bounded)) {
    signals.push({
      code: "ACCOUNT_ACCESS_SECRET_REQUEST",
      severity: "critical",
      title: "Account-access secret requested",
      detail: "Never give a password, one-time code, recovery code or seed phrase to someone who contacted you unexpectedly.",
    });
  }

  return {
    schemaVersion: 1,
    categories,
    phoneNumbers,
    remoteAccessTools: [...remoteAccessTools],
    requestedPaymentMethods,
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
