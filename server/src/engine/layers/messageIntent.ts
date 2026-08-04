import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import type { LayerResult } from "../verdict.js";

/**
 * Layer 3 — Message-intent analysis (spec Section 5).
 * Combined phrase + context rules only — spec explicitly forbids scoring
 * on a single keyword. Each rule below requires co-occurrence of an
 * "intent phrase" with a "pressure/action phrase" in the same message.
 */

interface IntentRule {
  code: string;
  category: string;
  intentPhrases: RegExp[];
  pressurePhrases: RegExp[];
  score: number;
  description: string;
}

const RULES: IntentRule[] = [
  {
    code: "CREDENTIAL_PHISH_INTENT",
    category: "credential_phishing",
    intentPhrases: [/password/i, /verify your account/i, /confirm your identity/i, /one[- ]time (code|passcode)/i, /recovery code/i, /seed phrase/i],
    pressurePhrases: [/within 24 hours/i, /account (will be|has been) (suspended|locked|disabled)/i, /unusual (sign-?in|activity)/i, /click (here|below) to/i],
    score: 3,
    description: "Message asks for credentials/OTP under time or suspension pressure.",
  },
  {
    code: "CALLBACK_SCAM_INTENT",
    category: "callback",
    intentPhrases: [/invoice/i, /subscription (renewed|charged)/i, /your (order|purchase)/i, /refund/i],
    pressurePhrases: [/call (us|now|the number below)/i, /\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}/, /if you did not authorize/i],
    score: 3,
    description: "Fake invoice/refund/subscription notice paired with a callback phone number.",
  },
  {
    code: "BEC_INTENT",
    category: "business_email_compromise",
    intentPhrases: [/wire transfer/i, /gift cards?/i, /update.{0,15}(bank|payroll|direct deposit)/i, /urgent(ly)? need you/i],
    pressurePhrases: [/are you available/i, /keep this (confidential|between us)/i, /can you do this (now|right away)/i, /don'?t (call|discuss)/i],
    score: 4,
    description: "Executive-impersonation payment-diversion pattern (BEC).",
  },
  {
    code: "CRYPTO_SCAM_INTENT",
    category: "cryptocurrency",
    intentPhrases: [/bitcoin/i, /\bBTC\b/, /wallet/i, /crypto(currency)?/i, /seed phrase/i, /investment platform/i],
    pressurePhrases: [/guaranteed returns?/i, /double your/i, /act (now|fast)/i, /limited (time|spots)/i, /validate your wallet/i],
    score: 4,
    description: "Cryptocurrency investment/wallet-validation pressure pattern.",
  },
  {
    code: "DELIVERY_PAYMENT_INTENT",
    category: "delivery_payment",
    intentPhrases: [/package/i, /parcel/i, /customs (fee|duty)/i, /toll/i, /redelivery/i, /shipment/i],
    pressurePhrases: [/pay (a small )?fee/i, /within \d+ (hours|days)/i, /will be returned/i, /update your (address|payment)/i],
    score: 3,
    description: "Delivery/customs-fee pressure pattern typical of parcel scams.",
  },
  {
    code: "ROMANCE_ADULT_INTENT",
    category: "romance_adult",
    intentPhrases: [/lonely/i, /looking for (love|companionship)/i, /view my (profile|photos)/i, /hookup/i, /adult content/i],
    pressurePhrases: [/click to (view|chat|connect)/i, /send (money|gift cards?)/i, /keep (this|it) (secret|private)/i, /exposed? (to|your) contacts/i],
    score: 3,
    description: "Romance/adult lure with redirect or sextortion-style pressure.",
  },
  {
    code: "JOB_SCAM_INTENT",
    category: "job_task",
    intentPhrases: [/work[- ]from[- ]home/i, /hiring/i, /task-based (pay|job)/i, /equipment (fee|deposit)/i, /overpayment/i],
    pressurePhrases: [/no experience (needed|required)/i, /start (today|immediately)/i, /send (back|us) the difference/i, /deposit the check/i],
    score: 3,
    description: "Job/task scam with upfront payment or check-overpayment pattern.",
  },
  {
    code: "GOV_LEGAL_INTENT",
    category: "government_legal",
    intentPhrases: [/tax refund/i, /\bIRS\b/i, /court/i, /warrant/i, /immigration/i, /benefits? (suspended|eligibility)/i],
    pressurePhrases: [/legal action/i, /arrest/i, /pay (immediately|now)/i, /failure to (respond|comply)/i],
    score: 4,
    description: "Government/legal-threat pressure pattern.",
  },
  {
    code: "PRIZE_REWARD_INTENT",
    category: "prize_reward",
    intentPhrases: [/you('ve| have) won/i, /lottery/i, /prize/i, /voucher/i, /loyalty points/i, /reward/i],
    pressurePhrases: [/claim (now|your prize)/i, /processing fee/i, /expires? (today|soon|in)/i, /advance fee/i],
    score: 3,
    description: "Prize/lottery pattern requiring an advance fee to claim.",
  },
  {
    code: "CLOUD_DOC_INTENT",
    category: "cloud_document",
    intentPhrases: [/shared a document/i, /docusign/i, /has sent you a file/i, /onedrive/i, /google drive/i, /review and sign/i],
    pressurePhrases: [/click to (view|sign|open)/i, /expires? (in|on)/i, /requires your (signature|action)/i],
    score: 2,
    description: "Fake shared-document notification typical of cloud-storage impersonation.",
  },
];

export function messageIntentLayer(envelope: CanonicalEnvelope): LayerResult {
  const haystack = `${envelope.subject}\n${envelope.textPreview ?? ""}\n${envelope.htmlSignals?.extractedText ?? ""}`;
  const evidence: LayerResult["evidence"] = [];
  const incomplete = envelope.textPreview === null && envelope.htmlSignals === null;

  for (const rule of RULES) {
    const hasIntent = rule.intentPhrases.some((p) => p.test(haystack));
    const hasPressure = rule.pressurePhrases.some((p) => p.test(haystack));
    if (hasIntent && hasPressure) {
      evidence.push({
        layer: "message_intent",
        code: rule.code,
        description: rule.description,
        scoreContribution: rule.score,
        source: "local",
      });
    }
  }

  return {
    layer: "message_intent",
    applicable: true,
    evidence,
    incomplete,
    incompleteReason: incomplete ? "No body text was available to analyze." : undefined,
    blocksSafeVerdict: incomplete, // genuinely missing content — must not be presented as "safe"
  };
}
