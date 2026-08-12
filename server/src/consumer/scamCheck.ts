import type { CanonicalEnvelope, FromField, LinkInfo } from "../canonical/envelope.js";
import type { SignedFeedEntry } from "../engine/layers/globalIntelligence.js";
import { InMemoryPersonalPolicyStore, type PersonalPolicySnapshot } from "../engine/layers/personalRules.js";
import { scanMessage, type ResponseAction } from "../engine/pipeline.js";
import type { Evidence, LayerResult, Verdict } from "../engine/verdict.js";
import { sha256Hex } from "../core/sha256.js";
import { analyzeHtmlInteractions, MAX_HTML_INTERACTION_CHARS, MAX_PLAIN_TEXT_INTERACTION_CHARS } from "../util/htmlInteraction.js";

export const CONSUMER_SCAM_CHECK_SCHEMA_VERSION = 1;
export const MAX_CONSUMER_SCAM_CHECK_REQUEST_BYTES = 1024 * 1024;
const MAX_SUBJECT_CHARS = 16_384;
const MAX_URL_CHARS = 8_192;
const MAX_SENDER_CHARS = 4_096;

export type ScamCheckKind = "message" | "url";
export type EvidenceStrength = "limited" | "moderate" | "strong";

/** Untrusted user-submitted content only. Trusted policy/intelligence are injected separately. */
export interface ConsumerScamCheckRequestV1 {
  schemaVersion: 1;
  kind: ScamCheckKind;
  text?: string;
  html?: string;
  subject?: string;
  url?: string;
  sender?: {
    displayName?: string | null;
    address?: string | null;
  };
}

export interface ConsumerScamCheckDependencies {
  /** Account-local policy from the trusted local repository, never from request JSON. */
  personalPolicy?: PersonalPolicySnapshot;
  /** Already-verified signed feed entries from the trusted feed cache, or null when unavailable. */
  intelligenceEntries?: SignedFeedEntry[] | null;
}

export interface ConsumerScamExplanationV1 {
  headline: string;
  summary: string;
  scamCategory: string | null;
  evidenceStrength: EvidenceStrength;
  strongestSignals: Array<{
    code: string;
    description: string;
    source: Evidence["source"];
  }>;
  limitations: string[];
  safeNextActions: string[];
}

export interface ConsumerScamCheckResponseV1 {
  schemaVersion: 1;
  verdict: Verdict;
  action: ResponseAction;
  score: number;
  confirmedByRule: boolean;
  evidence: Evidence[];
  layerResults: LayerResult[];
  explanation: ConsumerScamExplanationV1;
}

export class ConsumerScamCheckError extends Error {
  constructor(readonly code: "invalid_request" | "request_too_large") {
    super(code === "request_too_large"
      ? "Scam Check input exceeds the accepted local resource limit."
      : "Scam Check input is invalid.");
    this.name = "ConsumerScamCheckError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function boundedOptionalString(value: unknown, maxChars: number): boolean {
  return value === undefined || (typeof value === "string" && value.length <= maxChars);
}

function validSender(value: unknown): boolean {
  if (value === undefined) return true;
  if (!isRecord(value)) return false;
  const keys = Object.keys(value);
  if (keys.some((key) => key !== "displayName" && key !== "address")) return false;
  return (value.displayName === undefined || value.displayName === null || (typeof value.displayName === "string" && value.displayName.length <= MAX_SENDER_CHARS))
    && (value.address === undefined || value.address === null || (typeof value.address === "string" && value.address.length <= MAX_SENDER_CHARS));
}

export function assertConsumerScamCheckRequest(input: unknown): asserts input is ConsumerScamCheckRequestV1 {
  let serialized: string;
  try { serialized = JSON.stringify(input); }
  catch { throw new ConsumerScamCheckError("invalid_request"); }
  if (new TextEncoder().encode(serialized).length > MAX_CONSUMER_SCAM_CHECK_REQUEST_BYTES) {
    throw new ConsumerScamCheckError("request_too_large");
  }
  if (!isRecord(input)) throw new ConsumerScamCheckError("invalid_request");
  const allowed = new Set(["schemaVersion", "kind", "text", "html", "subject", "url", "sender"]);
  if (Object.keys(input).some((key) => !allowed.has(key))) throw new ConsumerScamCheckError("invalid_request");
  if (input.schemaVersion !== CONSUMER_SCAM_CHECK_SCHEMA_VERSION || (input.kind !== "message" && input.kind !== "url")) {
    throw new ConsumerScamCheckError("invalid_request");
  }
  if (!boundedOptionalString(input.text, MAX_PLAIN_TEXT_INTERACTION_CHARS)
    || !boundedOptionalString(input.html, MAX_HTML_INTERACTION_CHARS)
    || !boundedOptionalString(input.subject, MAX_SUBJECT_CHARS)
    || !boundedOptionalString(input.url, MAX_URL_CHARS)
    || !validSender(input.sender)) {
    throw new ConsumerScamCheckError("invalid_request");
  }
  const hasMessageContent = Boolean(
    (typeof input.text === "string" && input.text.trim())
      || (typeof input.html === "string" && input.html.trim())
      || (typeof input.subject === "string" && input.subject.trim()),
  );
  if (input.kind === "message" && !hasMessageContent) throw new ConsumerScamCheckError("invalid_request");
  if (input.kind === "url" && !(typeof input.url === "string" && input.url.trim())) throw new ConsumerScamCheckError("invalid_request");
}

function senderField(sender: ConsumerScamCheckRequestV1["sender"]): FromField {
  const address = sender?.address?.trim() || null;
  let domain: string | null = null;
  if (address) {
    const at = address.lastIndexOf("@");
    if (at >= 0 && at < address.length - 1) domain = address.slice(at + 1).trim().toLowerCase() || null;
  }
  return {
    displayName: sender?.displayName?.trim() || null,
    address,
    domain,
  };
}

function directUrlLink(raw: string): LinkInfo {
  const value = raw.trim();
  let normalized = value;
  try { normalized = new URL(/^www\./i.test(value) ? `https://${value}` : value).toString(); }
  catch { /* Link analysis retains malformed input as bounded evidence. */ }
  return {
    visibleText: value,
    rawUrl: value,
    normalizedUrl: normalized,
    claimedBrand: null,
    brandDomainMismatch: null,
    source: "body",
    interaction: "navigation",
  };
}

function dedupeLinks(links: LinkInfo[]): LinkInfo[] {
  const seen = new Set<string>();
  const result: LinkInfo[] = [];
  for (const link of links) {
    const key = `${link.interaction ?? "navigation"}\0${link.normalizedUrl || link.rawUrl}\0${link.visibleText ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(link);
  }
  return result.slice(0, 256);
}

function buildSubmittedEnvelope(input: ConsumerScamCheckRequestV1): CanonicalEnvelope {
  const text = input.text ?? null;
  const html = input.html ?? null;
  const interactions = analyzeHtmlInteractions(html, text);
  const links = dedupeLinks([
    ...interactions.links,
    ...(input.url?.trim() ? [directUrlLink(input.url)] : []),
  ]);
  const identityMaterial = JSON.stringify({
    kind: input.kind,
    subject: input.subject ?? "",
    text: input.text ?? "",
    html: input.html ?? "",
    url: input.url ?? "",
    sender: input.sender ?? null,
  });
  const id = sha256Hex(identityMaterial);
  const sizeBytes = new TextEncoder().encode(identityMaterial).length;
  const htmlText = html
    ? html.replace(/<script\b[\s\S]*?<\/script\s*>/gi, " ")
      .replace(/<style\b[\s\S]*?<\/style\s*>/gi, " ")
      .replace(/<[^>]*>/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, MAX_PLAIN_TEXT_INTERACTION_CHARS)
    : null;

  return {
    // Submitted content is deliberately routed through the least-trusting
    // canonical provider context. It never fabricates provider authentication.
    provider: "imap",
    accountProof: `submitted:${id}`,
    messageId: `submitted:${id}`,
    providerNativeId: `submitted:${id}`,
    folder: "other",
    providerFolderName: "consumer-scam-check",
    from: senderField(input.sender),
    replyTo: null,
    subject: input.subject ?? "",
    date: new Date(0).toISOString(),
    authentication: {
      spf: "unknown",
      dkim: "unknown",
      dmarc: "unknown",
      arc: "unknown",
      providerTrust: "unknown",
    },
    textPreview: text,
    htmlSignals: html
      ? {
          extractedText: htmlText,
          hrefs: interactions.htmlHrefs,
          hasForm: interactions.hasForm,
          hasPasswordField: interactions.hasPasswordField,
        }
      : null,
    links,
    attachments: [],
    listHeaders: {
      listId: null,
      listUnsubscribe: null,
      listUnsubscribePost: null,
    },
    threadContext: {
      isFirstContact: true,
      threadContinuityBroken: false,
      replyToChangedMidThread: false,
    },
    parseStatus: interactions.incomplete ? "partial" : "complete",
    parseNotes: interactions.incompleteReasons,
    diagnostics: {
      fetchedAt: new Date(0).toISOString(),
      sizeBytes,
      encoding: html && text ? "mixed" : "plain",
      contentCoverage: interactions.incomplete ? "insufficient" : "complete",
    },
  };
}

const CATEGORY_BY_CODE: Array<[RegExp, string]> = [
  [/CREDENTIAL|PASSWORD|OTP|LOGIN/i, "credential_phishing"],
  [/CALLBACK|REFUND|SUBSCRIPTION/i, "callback_refund"],
  [/BEC|PAYMENT_DIVERSION|WIRE|GIFT_CARD/i, "payment_diversion"],
  [/CRYPTO|WALLET|SEED/i, "cryptocurrency"],
  [/DELIVERY|PARCEL|TOLL|SHIPMENT/i, "delivery_payment"],
  [/ROMANCE|ADULT|PROFILE_LURE/i, "romance_social"],
  [/JOB|TASK|OVERPAY/i, "job_task"],
  [/GOV|LEGAL|ARREST|WARRANT/i, "government_legal"],
  [/PRIZE|LOTTERY|ADVANCE_FEE|REWARD/i, "prize_advance_fee"],
  [/CLOUD_DOC|DOCUMENT/i, "cloud_document"],
  [/PUNYCODE|LOOKALIKE|IMPERSONATION|DISPLAYED_VS_ACTUAL/i, "impersonation_phishing"],
  [/RAW_IP|URL_SHORTENER|MALFORMED_URL|UNSAFE_LINK|NON_WEB_LINK/i, "suspicious_link"],
  [/GLOBAL_.*THREAT|COMMUNITY/i, "known_campaign"],
];

function scamCategory(evidence: Evidence[]): string | null {
  const ordered = [...evidence].sort((a, b) => b.scoreContribution - a.scoreContribution);
  for (const item of ordered) {
    for (const [pattern, category] of CATEGORY_BY_CODE) if (pattern.test(item.code)) return category;
  }
  return null;
}

function evidenceStrength(verdict: Verdict, confirmedByRule: boolean, evidence: Evidence[]): EvidenceStrength {
  if (confirmedByRule || verdict === "confirmed_threat") return "strong";
  const positive = evidence.filter((item) => item.scoreContribution > 0);
  const max = positive.reduce((value, item) => Math.max(value, item.scoreContribution), 0);
  if (verdict === "high_risk" || max >= 4 || positive.length >= 3) return "strong";
  if (verdict === "review" || max >= 2 || positive.length >= 2) return "moderate";
  return "limited";
}

function limitations(layerResults: LayerResult[]): string[] {
  const result = [
    "This check analyzes only the content you submitted; it does not have trusted mailbox transport/authentication provenance unless the item came through a connected mailbox scan.",
  ];
  for (const layer of layerResults) {
    if (!layer.incomplete || !layer.incompleteReason) continue;
    if (!result.includes(layer.incompleteReason)) result.push(layer.incompleteReason);
  }
  return result.slice(0, 8);
}

function safeNextActions(verdict: Verdict): string[] {
  if (verdict === "confirmed_threat" || verdict === "high_risk") {
    return [
      "Do not click links, open attachments, call numbers, send money, share codes, or enter credentials from the suspicious content.",
      "If the message claims to be from an organization, open its official app or independently type its known official website instead of using contact details from the message.",
      "If money or account access may already be affected, contact the relevant bank/service through an independently verified channel and change compromised credentials from a trusted device.",
    ];
  }
  if (verdict === "review" || verdict === "unknown") {
    return [
      "Treat the content cautiously until you verify the sender or organization through an independent channel.",
      "Do not use phone numbers or links supplied by the suspicious content for verification.",
    ];
  }
  return [
    "No strong scam signal was found in the submitted material, but this is not proof that the sender, account, or destination is genuine.",
    "For sensitive payments, credentials, recovery codes, or account changes, verify independently before acting.",
  ];
}

function explanation(params: {
  verdict: Verdict;
  confirmedByRule: boolean;
  evidence: Evidence[];
  layerResults: LayerResult[];
}): ConsumerScamExplanationV1 {
  const strongest = [...params.evidence]
    .filter((item) => item.scoreContribution > 0)
    .sort((a, b) => b.scoreContribution - a.scoreContribution)
    .slice(0, 5)
    .map((item) => ({ code: item.code, description: item.description, source: item.source }));
  const category = scamCategory(params.evidence);
  const headline = params.verdict === "confirmed_threat"
    ? "Known threat"
    : params.verdict === "high_risk"
      ? "High scam risk"
      : params.verdict === "review"
        ? "Suspicious — verify before acting"
        : params.verdict === "unknown"
          ? "Not enough trustworthy evidence"
          : "No strong scam signal found";
  const summary = strongest.length
    ? strongest.map((item) => item.description).join(" ")
    : "Email Shield did not observe a strong deterministic scam indicator in the submitted material.";
  return {
    headline,
    summary,
    scamCategory: category,
    evidenceStrength: evidenceStrength(params.verdict, params.confirmedByRule, params.evidence),
    strongestSignals: strongest,
    limitations: limitations(params.layerResults),
    safeNextActions: safeNextActions(params.verdict),
  };
}

export function evaluateConsumerScamCheck(
  input: unknown,
  deps: ConsumerScamCheckDependencies = {},
): ConsumerScamCheckResponseV1 {
  assertConsumerScamCheckRequest(input);
  const envelope = buildSubmittedEnvelope(input);
  const policy = new InMemoryPersonalPolicyStore();
  if (deps.personalPolicy) policy.restore(structuredClone(deps.personalPolicy));
  const intelligenceEntries = deps.intelligenceEntries === undefined
    ? null
    : deps.intelligenceEntries === null
      ? null
      : structuredClone(deps.intelligenceEntries);
  const result = scanMessage(envelope, {
    personalPolicy: policy,
    threatFeed: { getVerifiedEntries: () => intelligenceEntries },
  });
  return {
    schemaVersion: CONSUMER_SCAM_CHECK_SCHEMA_VERSION,
    verdict: result.scored.verdict,
    action: result.action,
    score: result.scored.score,
    confirmedByRule: result.scored.confirmedByRule,
    evidence: structuredClone(result.scored.evidence),
    layerResults: structuredClone(result.scored.layerResults),
    explanation: explanation({
      verdict: result.scored.verdict,
      confirmedByRule: result.scored.confirmedByRule,
      evidence: result.scored.evidence,
      layerResults: result.scored.layerResults,
    }),
  };
}
