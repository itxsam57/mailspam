import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import {
  hasAuthenticatedOrganizationalIdentity,
  isSharedMailboxDomain,
} from "../identitySignals.js";
import type { LayerResult } from "../verdict.js";

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
    description: "Invoice/refund/subscription notice is paired with callback pressure.",
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
    intentPhrases: [/tax refund/i, /government agency/i, /court/i, /warrant/i, /immigration/i, /benefits? (suspended|eligibility)/i],
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
    intentPhrases: [/shared a document/i, /electronic signature/i, /has sent you a file/i, /cloud drive/i, /review and sign/i],
    pressurePhrases: [/click to (view|sign|open)/i, /expires? (in|on)/i, /requires your (signature|action)/i],
    score: 2,
    description: "Shared-document notification uses urgency or forced-action language.",
  },
];

function pushUnique(evidence: LayerResult["evidence"], item: LayerResult["evidence"][number]) {
  if (!evidence.some((existing) => existing.code === item.code)) evidence.push(item);
}

export function messageIntentLayer(envelope: CanonicalEnvelope): LayerResult {
  const linkText = envelope.links.map((link) => `${link.visibleText ?? ""}\n${link.rawUrl}`).join("\n");
  const haystack = `${envelope.subject}\n${envelope.textPreview ?? ""}\n${envelope.htmlSignals?.extractedText ?? ""}\n${linkText}`;
  const subject = envelope.subject.trim();
  const evidence: LayerResult["evidence"] = [];
  const incomplete = envelope.textPreview === null && envelope.htmlSignals === null;

  for (const rule of RULES) {
    const hasIntent = rule.intentPhrases.some((pattern) => pattern.test(haystack));
    const hasPressure = rule.pressurePhrases.some((pattern) => pattern.test(haystack));
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

  const callbackIndex = evidence.findIndex((item) => item.code === "CALLBACK_SCAM_INTENT");
  if (callbackIndex >= 0) {
    const callbackContext =
      /(?:invoice|order|purchase|payment|refund|auto[- ]?debit|subscription).{0,80}(?:call|\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}|not authorize)/i.test(haystack) ||
      /(?:call|not authorize).{0,80}(?:invoice|order|purchase|payment|refund|subscription)/i.test(haystack) ||
      /(?:invoice|order|payment|refund|auto[- ]?debit)/i.test(subject);
    if (!callbackContext) evidence.splice(callbackIndex, 1);
  }

  // Any previously unseen organization can send a legitimate password or
  // account-security notice. Authentication + organizational alignment—not a
  // brand name in source code—suppresses the generic credential phrase alone.
  // Link and identity layers still score cross-domain actions or deception.
  if (hasAuthenticatedOrganizationalIdentity(envelope)) {
    const credentialIndex = evidence.findIndex((item) => item.code === "CREDENTIAL_PHISH_INTENT");
    if (credentialIndex >= 0) evidence.splice(credentialIndex, 1);
  }

  const romanceContext = /(?:let'?s meet|i(?:'|’)m waiting for you|meet me|private photos?|looking for someone|lonely)/i.test(haystack);
  const profileAction = /(?:view|see|open|visit).{0,24}(?:my\s+)?(?:profile|photos?)/i.test(haystack);
  const hasExternalLink = envelope.links.some((link) => /^https?:\/\//i.test(link.normalizedUrl || link.rawUrl));
  const alreadyMatchedRomance = evidence.some((item) => item.code === "ROMANCE_ADULT_INTENT");
  if (romanceContext && profileAction && hasExternalLink && !alreadyMatchedRomance) {
    pushUnique(evidence, {
      layer: "message_intent",
      code: "PROFILE_LURE_REDIRECT",
      description: "Romance/profile lure directs the recipient to an external profile or photo link.",
      scoreContribution: 3,
      source: "local",
    });
  }

  const fromDomain = envelope.from.domain ?? "";
  const firstContactFreeMail = envelope.threadContext.isFirstContact && isSharedMailboxDomain(fromDomain);
  if (
    firstContactFreeMail &&
    /(?:meet new people|wanna see (?:my )?photos?|see photos? me|free right now|how can i contact you|what if i said i want you|do you like to meet|\bdates?\b|actual person)/i.test(subject)
  ) {
    pushUnique(evidence, {
      layer: "message_intent",
      code: "UNSOLICITED_ROMANCE_LURE",
      description: "A first-contact personal mailbox uses a romance or private-photo lure.",
      scoreContribution: 2,
      source: "local",
    });
  }

  if (
    /(?:evaluator|mystery)\s*shopper|shopping evaluator|driving your own car/i.test(haystack) &&
    /(?:earn|\$[4-9]\d{2}|per assignment|bonus)/i.test(haystack)
  ) {
    pushUnique(evidence, {
      layer: "message_intent",
      code: "UNSOLICITED_HIGH_PAY_JOB",
      description: "Unsolicited evaluator/shopper work promises unusually high payment.",
      scoreContribution: 3,
      source: "local",
    });
  }

  if (
    /(?:bitcoin|ethereum|\bBTC\b|\bETH\b|cryptocurrency|crypto)/i.test(haystack) &&
    /(?:earn\s+\d+(?:\.\d+)?%|\d+(?:\.\d+)?%\s+(?:interest|yield|apy)|win\s+free\s+(?:bitcoin|ethereum|crypto)|free\s+(?:bitcoin|ethereum|crypto).{0,30}(?:hour|daily|every)|guaranteed\s+(?:interest|yield|return))/i.test(haystack)
  ) {
    pushUnique(evidence, {
      layer: "message_intent",
      code: "CRYPTO_YIELD_REWARD_PROMOTION",
      description: "Unsolicited cryptocurrency promotion advertises yield, interest, or recurring free-coin rewards.",
      scoreContribution: 3,
      source: "local",
    });
  }

  if (firstContactFreeMail && /(?:your order|order received|invoice|receipt confirmation|payment confirmation|account reset)/i.test(subject)) {
    pushUnique(evidence, {
      layer: "message_intent",
      code: "COMMERCE_NOTICE_FROM_FREE_MAIL",
      description: "An unrelated personal mailbox sent an order, invoice, payment, or account notice.",
      scoreContribution: 2,
      source: "local",
    });
  }

  if (
    envelope.threadContext.isFirstContact &&
    /(?:flash reward|claim yours|free (?:medicare )?(?:kit|tool set|gift|reward)|claim your free)/i.test(subject)
  ) {
    pushUnique(evidence, {
      layer: "message_intent",
      code: "FREE_REWARD_LURE",
      description: "First-contact message advertises an unsolicited free reward or claim.",
      scoreContribution: 2,
      source: "local",
    });
  }

  return {
    layer: "message_intent",
    applicable: true,
    evidence,
    incomplete,
    incompleteReason: incomplete ? "No body text was available to analyze." : undefined,
    blocksSafeVerdict: incomplete,
  };
}
