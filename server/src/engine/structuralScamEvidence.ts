import type { LinkInfo } from "../canonical/envelope.js";
import { normalizeSecurityText } from "./securityText.js";

export type TransactionEvent =
  | "invoice"
  | "payment"
  | "purchase"
  | "refund"
  | "subscription"
  | "login"
  | "account_restriction"
  | "inheritance"
  | "job"
  | "prize"
  | "support_incident";

export type PaymentInstrument =
  | "bank_transfer"
  | "card"
  | "crypto"
  | "gift_card"
  | "cash_app"
  | "unknown_money";

export type RequestedAction =
  | "call"
  | "reply"
  | "open_link"
  | "scan_qr"
  | "pay"
  | "install_remote_access"
  | "send_otp"
  | "send_recovery_secret"
  | "send_gift_card_code"
  | "move_money";

export type PressureSignal =
  | "urgent"
  | "deadline"
  | "account_loss"
  | "secrecy"
  | "no_independent_contact"
  | "irreversible";

export interface StructuralScamInput {
  subject?: string | null;
  text?: string | null;
  htmlText?: string | null;
  displayName?: string | null;
  links?: ReadonlyArray<Pick<LinkInfo, "visibleText" | "rawUrl" | "normalizedUrl" | "source">>;
}

export interface StructuralScamFacts {
  events: TransactionEvent[];
  paymentInstruments: PaymentInstrument[];
  requestedActions: RequestedAction[];
  pressure: PressureSignal[];
  organizationClaims: string[];
}

const EVENT_ORDER: readonly TransactionEvent[] = [
  "invoice",
  "payment",
  "purchase",
  "refund",
  "subscription",
  "login",
  "account_restriction",
  "inheritance",
  "job",
  "prize",
  "support_incident",
];
const PAYMENT_ORDER: readonly PaymentInstrument[] = [
  "bank_transfer",
  "card",
  "crypto",
  "gift_card",
  "cash_app",
  "unknown_money",
];
const ACTION_ORDER: readonly RequestedAction[] = [
  "call",
  "reply",
  "open_link",
  "scan_qr",
  "pay",
  "install_remote_access",
  "send_otp",
  "send_recovery_secret",
  "send_gift_card_code",
  "move_money",
];
const PRESSURE_ORDER: readonly PressureSignal[] = [
  "urgent",
  "deadline",
  "account_loss",
  "secrecy",
  "no_independent_contact",
  "irreversible",
];

const TRANSMISSION = /\b(?:send|share|provide|tell|give|reply\s+with|read\s+back|forward|message|text)\b/u;
const NEGATED_TRANSMISSION = /\b(?:never|do\s+not|don't|dont)\s+(?:send|share|provide|tell|give|reply\s+with|read\s+back|forward)\b/u;
const GIFT_CARD = /\b(?:gift\s*cards?|giftcards?|store\s+cards?|vouchers?)\b/u;
const GIFT_CARD_SECRET = /\b(?:codes?|card\s+numbers?|numbers?|pins?|serials?)\b/u;
const IMAGE_OF_SECRET = /\b(?:photo|photos|picture|pictures|image|images|screenshot|snap)\b/u;
const OTP_SECRET = /\b(?:otp|one[- ]?time(?:\s+(?:verification|security|login|sign[- ]?in))?\s+(?:code|passcode)|verification\s+code|security\s+code|login\s+code|sign[- ]?in\s+code|passcode)\b/u;
const RECOVERY_SECRET = /\b(?:password|recovery\s+(?:code|key|phrase)|seed\s+phrase|private\s+key|backup\s+code)\b/u;
const REMOTE_TOOL = /\b(?:anydesk|teamviewer|quick\s+assist|screenconnect|connectwise\s+control|rustdesk|ultraviewer|remote\s+desktop)\b/u;
const REMOTE_ACTION = /\b(?:install|download|open|launch|run|start|allow|enable|grant|give)\b[^.!?\n]{0,80}\b(?:access|control|remote|anydesk|teamviewer|quick\s+assist|screenconnect|rustdesk|ultraviewer)\b|\b(?:allow|grant|give)\b[^.!?\n]{0,60}\b(?:us|me|support|agent|team)\b[^.!?\n]{0,40}\b(?:access|control)\b/u;

const DISPLAY_ROLE_SUFFIX = /\s+(?:billing|payments?|accounts?|support|security|fraud(?:\s+team)?|service(?:s)?|helpdesk|help\s+desk|admin(?:istration)?)$/u;
const SUBJECT_TRANSACTION = /^(?<claim>[\p{L}\p{N}][\p{L}\p{N} &'._-]{1,70}?)\s+(?:payment|invoice|purchase|order|refund|subscription|billing|security|account)\b/u;
const CLAIM_STOP_WORDS = new Set([
  "your",
  "the",
  "new",
  "urgent",
  "important",
  "payment",
  "invoice",
  "purchase",
  "order",
  "refund",
  "subscription",
  "billing",
  "security",
  "account",
]);

function normalizedParts(input: StructuralScamInput): {
  subject: string;
  displayName: string;
  full: string;
} {
  const subject = normalizeSecurityText(input.subject ?? "");
  const displayName = normalizeSecurityText(input.displayName ?? "");
  const pieces = [
    displayName,
    subject,
    normalizeSecurityText(input.text ?? ""),
    normalizeSecurityText(input.htmlText ?? ""),
    ...(input.links ?? []).map((link) => normalizeSecurityText(link.visibleText ?? "")),
  ].filter(Boolean);
  return { subject, displayName, full: pieces.join(" ") };
}

function ordered<T extends string>(seen: ReadonlySet<T>, order: readonly T[]): T[] {
  return order.filter((value) => seen.has(value));
}

function addEventFacts(text: string, seen: Set<TransactionEvent>): void {
  if (/\binvoice\b/u.test(text)) seen.add("invoice");
  if (/\b(?:payment|paid|payable|billing|transaction)\b/u.test(text)) seen.add("payment");
  if (/\b(?:purchase|purchased|order|ordered|checkout|receipt)\b/u.test(text)) seen.add("purchase");
  if (/\b(?:refund|reimbursement|money\s+back)\b/u.test(text)) seen.add("refund");
  if (/\b(?:subscription|renewal|membership)\b/u.test(text)) seen.add("subscription");
  if (/\b(?:login|log[- ]?in|sign[- ]?in|signed\s+in)\b/u.test(text)) seen.add("login");
  if (/\baccount\b[^.!?\n]{0,70}\b(?:suspend(?:ed|ion)?|lock(?:ed|out)?|restrict(?:ed|ion)?|disable(?:d)?|close(?:d)?|terminate(?:d|ion)?)\b|\b(?:suspend(?:ed|ion)?|lock(?:ed|out)?|restrict(?:ed|ion)?|disable(?:d)?|close(?:d)?|terminate(?:d|ion)?)\b[^.!?\n]{0,70}\baccount\b/u.test(text)) {
    seen.add("account_restriction");
  }
  if (/\b(?:inheritance|beneficiary|estate\s+funds?)\b/u.test(text)) seen.add("inheritance");
  if (/\b(?:job\s+offer|employment|recruit(?:er|ment)|hiring|vacancy)\b/u.test(text)) seen.add("job");
  if (/\b(?:prize|winner|winnings|lottery|sweepstakes)\b/u.test(text)) seen.add("prize");
  if (/\b(?:support|help\s*desk|fraud\s+team|security\s+department|technical\s+assistance)\b/u.test(text)) seen.add("support_incident");
}

function addPaymentFacts(text: string, seen: Set<PaymentInstrument>): void {
  if (/\b(?:wire(?:d|ing)?|bank\s+transfer|transfer\s+(?:the\s+)?funds?|bank\s+account\s+transfer)\b/u.test(text)) seen.add("bank_transfer");
  if (/\b(?:credit|debit)\s+cards?\b|\bcard\s+payment\b/u.test(text)) seen.add("card");
  if (/\b(?:bitcoin|btc|crypto(?:currency)?|usdt|tether|ethereum|eth|stablecoin|digital\s+currency)\b/u.test(text)) seen.add("crypto");
  if (GIFT_CARD.test(text)) seen.add("gift_card");
  if (/\b(?:cash\s*app|venmo|zelle|paypal|friends?\s+and\s+family)\b/u.test(text)) seen.add("cash_app");
  if (/\b(?:money|funds?|amount|dollars?|euros?|pounds?|usd|eur|gbp)\b/u.test(text)) seen.add("unknown_money");
}

function hasGiftCardExfiltration(text: string): boolean {
  if (!GIFT_CARD.test(text) || NEGATED_TRANSMISSION.test(text)) return false;
  const hasSecretArtifact = GIFT_CARD_SECRET.test(text) || (IMAGE_OF_SECRET.test(text) && /\b(?:card|voucher|code|number)\b/u.test(text));
  return hasSecretArtifact && (TRANSMISSION.test(text) || /\b(?:photo|photos|picture|pictures|image|images|screenshot)\b[^.!?\n]{0,50}\b(?:to\s+me|to\s+us|back|after|once)\b/u.test(text));
}

function hasOtpExfiltration(text: string): boolean {
  if (!OTP_SECRET.test(text) || NEGATED_TRANSMISSION.test(text)) return false;
  return TRANSMISSION.test(text);
}

function hasRecoverySecretExfiltration(text: string): boolean {
  if (!RECOVERY_SECRET.test(text) || NEGATED_TRANSMISSION.test(text)) return false;
  return TRANSMISSION.test(text);
}

function addActionFacts(text: string, seen: Set<RequestedAction>, paymentFacts: ReadonlySet<PaymentInstrument>): void {
  if (/\b(?:call|phone|dial)\b/u.test(text)) seen.add("call");
  if (/\b(?:reply|respond)\b/u.test(text)) seen.add("reply");
  if (/\b(?:click|open|visit|follow)\b[^.!?\n]{0,45}\b(?:link|url|website|portal|page)\b/u.test(text)) seen.add("open_link");
  if (/\b(?:scan|open)\b[^.!?\n]{0,35}\bqr\b/u.test(text)) seen.add("scan_qr");

  const paymentInstruction = /\b(?:pay|send|transfer|wire|remit)\b[^.!?\n]{0,100}\b(?:money|funds?|payment|amount|usd|eur|gbp|dollars?|euros?|pounds?|bitcoin|btc|crypto|usdt|wallet|gift\s*cards?|vouchers?)\b|\b(?:buy|purchase|obtain|get|pick\s+up)\b[^.!?\n]{0,70}\b(?:gift\s*cards?|vouchers?)\b/u;
  if (paymentInstruction.test(text) || (paymentFacts.has("crypto") && /\b(?:send|pay|transfer)\b/u.test(text))) seen.add("pay");

  if (REMOTE_TOOL.test(text) && REMOTE_ACTION.test(text)) seen.add("install_remote_access");
  if (hasOtpExfiltration(text)) seen.add("send_otp");
  if (hasRecoverySecretExfiltration(text)) seen.add("send_recovery_secret");
  if (hasGiftCardExfiltration(text)) seen.add("send_gift_card_code");
  if (/\b(?:move|transfer|wire|send)\b[^.!?\n]{0,80}\b(?:money|funds?|balance|amount|bank|wallet)\b/u.test(text)) seen.add("move_money");
}

function addPressureFacts(text: string, seen: Set<PressureSignal>): void {
  if (/\b(?:urgent|urgently|immediately|asap|right\s+away|now|today|without\s+delay)\b/u.test(text)) seen.add("urgent");
  if (/\bwithin\s+\d{1,4}\s+(?:minutes?|hours?|days?)\b|\b(?:before|by)\s+(?:today|tonight|end\s+of\s+day|eod|\d{1,2}(?::\d{2})?\s*(?:am|pm)?)\b|\bexpires?\s+(?:in|within)\b/u.test(text)) seen.add("deadline");
  if (/\baccount\b[^.!?\n]{0,80}\b(?:will\s+be\s+)?(?:suspend(?:ed)?|lock(?:ed)?|restrict(?:ed)?|disable(?:d)?|close(?:d)?|terminate(?:d)?)\b|\b(?:lose|loss\s+of)\b[^.!?\n]{0,40}\baccount\b/u.test(text)) seen.add("account_loss");
  if (/\b(?:keep\s+this\s+between\s+us|keep\s+it\s+between\s+us|do\s+not\s+tell|don't\s+tell|dont\s+tell|do\s+not\s+share\s+this|confidential|secretly|keep\s+this\s+secret)\b/u.test(text)) seen.add("secrecy");
  if (/\b(?:do\s+not|don't|dont|no\s+need\s+to)\s+(?:call|contact|check|verify|speak\s+with|ask)\b/u.test(text)) seen.add("no_independent_contact");
  if (/\b(?:cannot|can't|cant|will\s+not|won't|wont)\s+be\s+(?:reversed|refunded|recovered|cancelled|canceled)\b|\b(?:irreversible|non[- ]?refundable|no\s+chargebacks?|final\s+and\s+irreversible)\b/u.test(text)) seen.add("irreversible");
}

function cleanOrganizationClaim(value: string): string | null {
  const candidate = normalizeSecurityText(value)
    .replace(DISPLAY_ROLE_SUFFIX, "")
    .replace(/^[\s:;,._-]+|[\s:;,._-]+$/gu, "")
    .replace(/\s+/gu, " ")
    .trim();
  if (!candidate || candidate.length < 2 || candidate.length > 72) return null;
  const words = candidate.split(" ").filter(Boolean);
  if (words.length > 7 || words.every((word) => CLAIM_STOP_WORDS.has(word))) return null;
  return candidate;
}

function organizationClaims(subject: string, displayName: string): string[] {
  const seen = new Set<string>();
  if (DISPLAY_ROLE_SUFFIX.test(displayName)) {
    const fromDisplay = cleanOrganizationClaim(displayName);
    if (fromDisplay) seen.add(fromDisplay);
  }
  const match = SUBJECT_TRANSACTION.exec(subject);
  if (match?.groups?.claim) {
    const fromSubject = cleanOrganizationClaim(match.groups.claim);
    if (fromSubject) seen.add(fromSubject);
  }
  return [...seen].sort((left, right) => left.localeCompare(right, "en"));
}

export function extractStructuralScamFacts(input: StructuralScamInput): StructuralScamFacts {
  const normalized = normalizedParts(input);
  const events = new Set<TransactionEvent>();
  const payments = new Set<PaymentInstrument>();
  const actions = new Set<RequestedAction>();
  const pressure = new Set<PressureSignal>();

  addEventFacts(normalized.full, events);
  addPaymentFacts(normalized.full, payments);
  addActionFacts(normalized.full, actions, payments);
  addPressureFacts(normalized.full, pressure);

  return {
    events: ordered(events, EVENT_ORDER),
    paymentInstruments: ordered(payments, PAYMENT_ORDER),
    requestedActions: ordered(actions, ACTION_ORDER),
    pressure: ordered(pressure, PRESSURE_ORDER),
    organizationClaims: organizationClaims(normalized.subject, normalized.displayName),
  };
}
