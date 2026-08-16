import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import { sameOrganizationalDomain } from "../../util/domainRelation.js";
import {
  hasAuthenticatedOrganizationalIdentity,
  isSharedMailboxDomain,
} from "../identitySignals.js";
import { organizationClaimAligned } from "./identityImpersonation.js";
import { structuralConsistencyEvidenceCodes } from "./structuralConsistency.js";
import type { LayerResult } from "../verdict.js";
import { normalizeSecurityText } from "../securityText.js";

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
    intentPhrases: [
      /password/i,
      /verify your account/i,
      /confirm your identity/i,
      /one[- ]time (code|passcode)/i,
      /one[- ]time (?:verification|security|login|sign[- ]?in) (?:code|passcode)/i,
      /recovery code/i,
      /seed phrase/i,
    ],
    pressurePhrases: [
      /within 24 hours/i,
      /account (will be|has been) (suspended|locked|disabled)/i,
      /account (?:lock|suspension|restriction)/i,
      /unusual (sign-?in|activity)/i,
      /click (here|below) to/i,
    ],
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
    pressurePhrases: [
      /guaranteed returns?/i,
      /double your/i,
      /act (now|fast)/i,
      /limited (time|spots)/i,
      /validate your wallet/i,
      /within \d+ (?:minutes?|hours?)/i,
      /(?:cannot|can't|cant) be reversed/i,
    ],
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
  {
    code: "CALENDAR_INVITE_SCAM_INTENT",
    category: "calendar_invite",
    intentPhrases: [/calendar (?:invite|invitation)/i, /meeting invitation/i, /event invitation/i, /invited you to (?:a |an )?(?:meeting|event|calendar)/i, /added you to (?:a |an )?calendar/i],
    pressurePhrases: [/sign in to (?:view|join|accept)/i, /verify (?:your )?account/i, /enter (?:your )?(?:password|one[- ]time code|otp)/i, /pay (?:a |the )?(?:fee|deposit)/i, /send (?:a )?(?:gift card|bank transfer|wire transfer)/i],
    score: 3,
    description: "Calendar/meeting invitation is paired with a credential, payment, or value-transfer demand that should be verified outside the invitation.",
  },
  {
    code: "BROWSER_EXTENSION_DOWNLOAD_LURE",
    category: "malicious_download",
    intentPhrases: [/browser extension/i, /chrome extension/i, /edge extension/i, /firefox add[- ]?on/i, /install (?:this |the )?extension/i, /download (?:this |the )?(?:installer|security tool|update)/i],
    pressurePhrases: [/install (?:it |this |now )?(?:now|immediately|required)/i, /required to (?:view|open|continue|verify|secure)/i, /download and (?:run|open|install)/i, /disable (?:antivirus|security|protection)/i, /allow (?:unknown|unverified) (?:app|source)/i],
    score: 3,
    description: "Message pressures the recipient to install a browser extension or downloaded program as a prerequisite for access, verification, or security.",
  },
];

/**
 * High-signal concepts in frequently targeted languages. A rule requires both
 * an intent and a pressure/action concept, which avoids classifying ordinary
 * translated account, delivery, or prize wording by a single keyword.
 */
const MULTILINGUAL_RULES: IntentRule[] = [
  {
    code: "MULTILINGUAL_CREDENTIAL_PHISH_INTENT",
    category: "credential_phishing",
    intentPhrases: [
      /(?:پاس\s*ورڈ|رمز\s*عبور|كلمة\s*المرور|पासवर्ड|contraseña|mot\s+de\s+passe|passwort|senha)/u,
      /(?:تصديق|تحقق|تصدیق|تصدیق\s+کریں|सत्यापित\s+करें|verificar\s+(?:su\s+)?cuenta|vérifiez\s+(?:votre\s+)?compte|konto\s+bestätigen|verificar\s+(?:a\s+)?conta)/u,
    ],
    pressurePhrases: [
      /(?:فورا|فوری|الآن|على\s+الفور|तुरंत|inmediatamente|immédiatement|sofort|imediatamente)/u,
      /(?:حساب|اکاؤنٹ|खाता|cuenta|compte|konto|conta).{0,36}(?:تعليق|بند|معطل|सस्पेंड|बंद|suspend|bloqu|gesperrt|desativad)/u,
    ],
    score: 3,
    description: "Message combines a multilingual credential/account-verification request with urgency or account-loss pressure.",
  },
  {
    code: "MULTILINGUAL_ADVANCE_FEE_INTENT",
    category: "advance_fee",
    intentPhrases: [
      /(?:جائزة|يانصيب|انعام|انعام\s+جیت|انعامی\s+رقم|पुरस्कार|लॉटरी|premio|lotería|prix|loterie|gewinn|lotterie|prêmio|loteria)/u,
    ],
    pressurePhrases: [
      /(?:رسوم|فيس|فیس|फीस|tarifa|tasa|frais|gebühr|taxa).{0,32}(?:ادفع|ادا|پیمنٹ|भुगतान|pagar|payez|zahlen|pague)/u,
      /(?:اطالب|حاصل\s+کریں|दावा\s+करें|reclamar|réclamez|beanspruchen|resgatar).{0,24}(?:الآن|فوری|अभी|ahora|maintenant|jetzt|agora)/u,
    ],
    score: 3,
    description: "Prize or lottery wording in another language is paired with a fee/payment or immediate-claim demand.",
  },
  {
    code: "MULTILINGUAL_PAYMENT_DIVERSION_INTENT",
    category: "payment_diversion",
    intentPhrases: [
      /(?:تحويل\s+بنكي|تحویل\s+رقم|بنک\s+ٹرانسفر|बैंक\s+ट्रांसफर|tarjeta(?:s)?\s+de\s+regalo|virement\s+bancaire|geschenkkarte|transferência\s+bancária)/u,
    ],
    pressurePhrases: [
      /(?:سرا|خفي|راز|خفیہ|गोपनीय|secreto|confidentiel|vertraulich|confidencial)/u,
      /(?:فورا|فوری|الآن|तुरंत|urgente|immédiatement|sofort|imediatamente)/u,
    ],
    score: 4,
    description: "A multilingual bank-transfer or gift-card request is paired with secrecy or urgency, consistent with payment diversion.",
  },
];

const FIRST_CONTACT_ROMANCE_PATTERN = /(?:meet new people|wanna see (?:my )?photos?|see photos? me|free right now|how can i contact you|what if i said i want you|do you like to meet|\bdates?\b|actual person)/i;
const HIGH_CONFIDENCE_ROMANCE_PATTERN = /(?:wanna see (?:my )?photos?|see (?:my )?(?:hot |private )?photos?|private photos?|what if i said i want you|i(?:'|’)m waiting for you|waiting for you.{0,40}(?:open|join|view)|(?:open|join|view).{0,40}(?:my )?(?:profile|photos?|groups?)|\b(?:nudes?|naked|hookup|sex|sext|fuck|pussy|tits?)\b)/i;
const EXPLICIT_ADULT_SITE_PATTERN = /(?:exclusive\s+adult(?:\s+dating)?\s+community|adult\s+(?:live\s+chat|dating|personal|secret)\s+(?:site|community)|one[- ]night\s+dates?|n\s*u\s*d\s*e\s+(?:my\s+)?photos?|(?:send|check|view)\s+(?:my\s+)?(?:nude|hot|private)\s+(?:pics?|photos?)|join\s+(?:my|our)\s+(?:adult\s+)?(?:group|community))/i;

function pushUnique(evidence: LayerResult["evidence"], item: LayerResult["evidence"][number]) {
  if (!evidence.some((existing) => existing.code === item.code)) evidence.push(item);
}

function hasAuthenticatedBulkMailContext(envelope: CanonicalEnvelope): boolean {
  return hasAuthenticatedOrganizationalIdentity(envelope) && Boolean(
    envelope.listHeaders.listId ||
    envelope.listHeaders.listUnsubscribe ||
    envelope.listHeaders.listUnsubscribePost,
  );
}

function structuralOwnsLegacyBec(envelope: CanonicalEnvelope): boolean {
  const codes = new Set(structuralConsistencyEvidenceCodes(envelope));
  return codes.has("GIFT_CARD_CODE_EXFILTRATION")
    || codes.has("IRREVERSIBLE_PAYMENT_PRESSURE")
    || codes.has("SECRECY_PAYMENT_DIVERSION");
}

export function messageIntentLayer(envelope: CanonicalEnvelope): LayerResult {
  const linkText = envelope.links.map((link) => `${link.visibleText ?? ""}\n${link.rawUrl}`).join("\n");
  const haystack = normalizeSecurityText(`${envelope.subject}\n${envelope.textPreview ?? ""}\n${envelope.htmlSignals?.extractedText ?? ""}\n${linkText}`);
  const subject = normalizeSecurityText(envelope.subject);
  const evidence: LayerResult["evidence"] = [];
  const incomplete = envelope.textPreview === null && envelope.htmlSignals === null;
  const structuralBecOwnership = structuralOwnsLegacyBec(envelope);

  for (const rule of RULES) {
    if (rule.code === "BEC_INTENT" && structuralBecOwnership) continue;
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

  for (const rule of MULTILINGUAL_RULES) {
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

  if (hasAuthenticatedOrganizationalIdentity(envelope) && organizationClaimAligned(envelope)) {
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

  const firstContact = envelope.threadContext.isFirstContact;
  const senderPreviouslySeenInScan = envelope.threadContext.senderPreviouslySeenInScan === true;
  const fromDomain = envelope.from.domain ?? "";
  const firstContactFreeMail = firstContact && isSharedMailboxDomain(fromDomain);
  if (firstContact && FIRST_CONTACT_ROMANCE_PATTERN.test(subject)) {
    pushUnique(evidence, {
      layer: "message_intent",
      code: "UNSOLICITED_ROMANCE_LURE",
      description: "A first-contact message uses an unsolicited romance or private-photo lure.",
      scoreContribution: 2,
      source: "local",
    });
  }

  const hasModerateRomanceEvidence = evidence.some((item) =>
    item.code === "UNSOLICITED_ROMANCE_LURE" ||
    item.code === "PROFILE_LURE_REDIRECT" ||
    item.code === "ROMANCE_ADULT_INTENT"
  );
  const hasHighConfidenceRomanceEvidence =
    HIGH_CONFIDENCE_ROMANCE_PATTERN.test(haystack) ||
    evidence.some((item) => item.code === "PROFILE_LURE_REDIRECT" || item.code === "ROMANCE_ADULT_INTENT");
  if (firstContact && hasModerateRomanceEvidence && hasHighConfidenceRomanceEvidence) {
    const currentRomanceScore = evidence
      .filter((item) => ["UNSOLICITED_ROMANCE_LURE", "PROFILE_LURE_REDIRECT", "ROMANCE_ADULT_INTENT"].includes(item.code))
      .reduce((sum, item) => sum + item.scoreContribution, 0);
    pushUnique(evidence, {
      layer: "message_intent",
      code: "HIGH_CONFIDENCE_ROMANCE_LURE",
      description: "The first-contact romance lure includes sexual/private-photo language or an external profile redirect.",
      scoreContribution: Math.max(0, 6 - currentRomanceScore),
      source: "local",
    });
  }

  const suspiciousReplyRoute = Boolean(
    envelope.replyTo?.domain &&
    envelope.from.domain &&
    !sameOrganizationalDomain(envelope.replyTo.domain, envelope.from.domain),
  );
  if (
    firstContact &&
    hasExternalLink &&
    suspiciousReplyRoute &&
    EXPLICIT_ADULT_SITE_PATTERN.test(haystack)
  ) {
    pushUnique(evidence, {
      layer: "message_intent",
      code: "UNSOLICITED_ADULT_SITE_CAMPAIGN",
      description: "A first-contact adult-site solicitation links externally while routing replies to an unrelated organization.",
      scoreContribution: 4,
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
    firstContact &&
    !senderPreviouslySeenInScan &&
    !hasAuthenticatedBulkMailContext(envelope) &&
    /(?:flash reward|claim yours|claim your free|(?:free|complimentary).{0,35}(?:medicare )?(?:kit|tool set|gift|reward))/i.test(subject)
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