import type { CanonicalEnvelope } from "../canonical/envelope.js";
import {
  MAX_COMMUNITY_FEED_ENTRIES,
  MAX_COMMUNITY_FEED_ENTRY_VALUE_CHARS,
  MAX_COMMUNITY_FEED_RULE_ID_CHARS,
  MAX_COMMUNITY_IDENTITY_ALIASES,
  MAX_COMMUNITY_IDENTITY_DOMAINS,
  MAX_COMMUNITY_IDENTITY_TEXT_CHARS,
  MAX_COMMUNITY_DOMAIN_CHARS,
} from "../community/resourceLimits.js";
import { scanMessage, type ResponseAction, type ScanResult } from "../engine/pipeline.js";
import {
  InMemoryPersonalPolicyStore,
  type PersonalPolicySnapshot,
} from "../engine/layers/personalRules.js";
import type { SignedFeedEntry } from "../engine/layers/globalIntelligence.js";
import type { LayerResult, ScoredMessage, Verdict } from "../engine/verdict.js";

export const PORTABLE_CORE_SCHEMA_VERSION = 1;
export const MAX_PORTABLE_CORE_REQUEST_BYTES = 4 * 1024 * 1024;
const MAX_POLICY_VALUES_PER_CLASS = 10_000;
const MAX_POLICY_VALUE_CHARS = 2_048;
const MAX_ENVELOPE_LINKS = 256;
const MAX_ENVELOPE_ATTACHMENTS = 64;
const MAX_ENVELOPE_NOTES = 256;
const MAX_ENVELOPE_TEXT_CHARS = 512 * 1024;

export type PortableIntelligenceSnapshot =
  | { state: "verified"; entries: SignedFeedEntry[] }
  | { state: "unavailable"; entries: null };

export interface PortableCoreRequestV1 {
  schemaVersion: 1;
  envelope: CanonicalEnvelope;
  personalPolicy: PersonalPolicySnapshot;
  intelligence: PortableIntelligenceSnapshot;
}

export interface PortableCoreResponseV1 {
  schemaVersion: 1;
  verdict: Verdict;
  score: number;
  confirmedByRule: boolean;
  action: ResponseAction;
  evidence: ScoredMessage["evidence"];
  layerResults: LayerResult[];
}

export class PortableCoreContractError extends Error {
  constructor(readonly code: "invalid_request" | "request_too_large") {
    super(code === "request_too_large"
      ? "Portable core request exceeds the accepted resource limit."
      : "Portable core request is invalid.");
    this.name = "PortableCoreContractError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function hasExactFields(value: Record<string, unknown>, required: string[], optional: string[] = []): boolean {
  const allowed = new Set([...required, ...optional]);
  return required.every((field) => Object.hasOwn(value, field)) && Object.keys(value).every((field) => allowed.has(field));
}

function boundedString(value: unknown, maxChars: number, nullable = false): boolean {
  return (nullable && value === null) || (typeof value === "string" && value.length <= maxChars);
}

function validStringArray(value: unknown, maxItems: number, maxChars: number): value is string[] {
  return Array.isArray(value) && value.length <= maxItems && value.every((item) => boundedString(item, maxChars));
}

function validPersonalPolicy(value: unknown): value is PersonalPolicySnapshot {
  if (!isRecord(value)) return false;
  const legacyFields = [
    "blockedSenders",
    "blockedDomains",
    "trustedSenders",
    "approvedExceptions",
    "unsubscribedActions",
    "reportedCampaigns",
  ];
  const extendedFields = [
    ...legacyFields,
    "catchTrashSenders",
    "catchTrashDomains",
  ];
  if (!hasExactFields(value, legacyFields) && !hasExactFields(value, extendedFields)) return false;
  for (const field of legacyFields) {
    if (!validStringArray(value[field], MAX_POLICY_VALUES_PER_CLASS, MAX_POLICY_VALUE_CHARS)) return false;
  }
  if (value.catchTrashSenders !== undefined && !validStringArray(value.catchTrashSenders, MAX_POLICY_VALUES_PER_CLASS, MAX_POLICY_VALUE_CHARS)) return false;
  if (value.catchTrashDomains !== undefined && !validStringArray(value.catchTrashDomains, MAX_POLICY_VALUES_PER_CLASS, MAX_POLICY_VALUE_CHARS)) return false;
  return true;
}

function validFeedEntry(value: unknown): value is SignedFeedEntry {
  if (!isRecord(value) || !boundedString(value.type, 32) || !boundedString(value.value, MAX_COMMUNITY_FEED_ENTRY_VALUE_CHARS) || !boundedString(value.ruleId, MAX_COMMUNITY_FEED_RULE_ID_CHARS)) return false;
  if (value.type === "identity") {
    return hasExactFields(value, ["type", "value", "aliases", "domains", "confirmedThreat", "ruleId"])
      && value.confirmedThreat === false
      && boundedString(value.value, MAX_COMMUNITY_IDENTITY_TEXT_CHARS)
      && validStringArray(value.aliases, MAX_COMMUNITY_IDENTITY_ALIASES, MAX_COMMUNITY_IDENTITY_TEXT_CHARS)
      && validStringArray(value.domains, MAX_COMMUNITY_IDENTITY_DOMAINS, MAX_COMMUNITY_DOMAIN_CHARS);
  }
  if (!["sender", "domain", "url", "reply_to_domain", "url_domain", "attachment_hash", "campaign"].includes(String(value.type))) return false;
  if (!hasExactFields(value, ["type", "value", "confirmedThreat", "ruleId"], ["independentReports", "firstSeen", "lastSeen"])) return false;
  if (typeof value.confirmedThreat !== "boolean") return false;
  if (value.independentReports !== undefined && (!Number.isSafeInteger(value.independentReports) || Number(value.independentReports) < 1)) return false;
  if (value.firstSeen !== undefined && !boundedString(value.firstSeen, 64)) return false;
  if (value.lastSeen !== undefined && !boundedString(value.lastSeen, 64)) return false;
  return true;
}

function validIntelligence(value: unknown): value is PortableIntelligenceSnapshot {
  if (!isRecord(value) || !hasExactFields(value, ["state", "entries"])) return false;
  if (value.state === "unavailable") return value.entries === null;
  return value.state === "verified"
    && Array.isArray(value.entries)
    && value.entries.length <= MAX_COMMUNITY_FEED_ENTRIES
    && value.entries.every(validFeedEntry);
}

const ENVELOPE_FIELDS = [
  "provider", "accountProof", "messageId", "providerNativeId", "folder", "providerFolderName",
  "from", "replyTo", "subject", "date", "authentication", "textPreview", "htmlSignals", "links",
  "attachments", "listHeaders", "threadContext", "parseStatus", "parseNotes", "diagnostics",
];

function validFromField(value: unknown): boolean {
  return isRecord(value)
    && hasExactFields(value, ["displayName", "address", "domain"])
    && boundedString(value.displayName, 4_096, true)
    && boundedString(value.address, 4_096, true)
    && boundedString(value.domain, 253, true);
}

function validAuthentication(value: unknown): boolean {
  if (!isRecord(value) || !hasExactFields(value, ["spf", "dkim", "dmarc", "arc"], ["providerTrust", "rawHeader"])) return false;
  if (!["pass", "fail", "softfail", "neutral", "none", "unknown"].includes(String(value.spf))) return false;
  if (!["pass", "fail", "none", "unknown"].includes(String(value.dkim))) return false;
  if (!["pass", "fail", "none", "unknown"].includes(String(value.dmarc))) return false;
  if (!["pass", "fail", "none", "unknown"].includes(String(value.arc))) return false;
  if (value.providerTrust !== undefined && !["trusted", "suspicious", "unknown"].includes(String(value.providerTrust))) return false;
  return value.rawHeader === undefined || boundedString(value.rawHeader, 16_384);
}

function validLink(value: unknown): boolean {
  return isRecord(value)
    && hasExactFields(value, ["visibleText", "rawUrl", "normalizedUrl", "claimedBrand", "brandDomainMismatch"], ["source", "interaction"])
    && boundedString(value.visibleText, 4_096, true)
    && boundedString(value.rawUrl, 8_192)
    && boundedString(value.normalizedUrl, 8_192)
    && boundedString(value.claimedBrand, 1_024, true)
    && (value.brandDomainMismatch === null || typeof value.brandDomainMismatch === "boolean")
    && (value.source === undefined || value.source === "body" || value.source === "qr")
    && (value.interaction === undefined || ["navigation", "form_action", "automatic_redirect"].includes(String(value.interaction)));
}

function validNonNegativeInteger(value: unknown, maximum: number): boolean {
  return Number.isSafeInteger(value) && Number(value) >= 0 && Number(value) <= maximum;
}

function validArchiveSecurityInspection(value: unknown): boolean {
  if (!isRecord(value) || !hasExactFields(value, [
    "format",
    "entryCount",
    "encryptedEntries",
    "executableOrScriptEntries",
    "macroCapableEntries",
    "nestedArchiveEntries",
    "declaredCompressedBytes",
    "declaredUncompressedBytes",
    "maximumCompressionRatio",
    "overResourceLimit",
    "incomplete",
    "reasons",
  ])) return false;
  return value.format === "zip"
    && validNonNegativeInteger(value.entryCount, 10_000)
    && validNonNegativeInteger(value.encryptedEntries, 10_000)
    && validNonNegativeInteger(value.executableOrScriptEntries, 10_000)
    && validNonNegativeInteger(value.macroCapableEntries, 10_000)
    && validNonNegativeInteger(value.nestedArchiveEntries, 10_000)
    && validNonNegativeInteger(value.declaredCompressedBytes, Number.MAX_SAFE_INTEGER)
    && validNonNegativeInteger(value.declaredUncompressedBytes, Number.MAX_SAFE_INTEGER)
    && typeof value.maximumCompressionRatio === "number"
    && Number.isFinite(value.maximumCompressionRatio)
    && value.maximumCompressionRatio >= 0
    && value.maximumCompressionRatio <= Number.MAX_SAFE_INTEGER
    && typeof value.overResourceLimit === "boolean"
    && typeof value.incomplete === "boolean"
    && validStringArray(value.reasons, 16, 1_024);
}

const STATIC_MALWARE_INDICATORS = new Set([
  "eicar_test_signature",
  "encoded_powershell_execution",
  "powershell_download_execute_chain",
  "script_host_download_execute_chain",
  "shell_download_execute_chain",
  "office_autoexec_execution_chain",
  "living_off_land_execution_chain",
]);

function validStaticMalwareInspection(value: unknown): boolean {
  return isRecord(value)
    && hasExactFields(value, ["risk", "indicators", "coverage"])
    && ["none", "suspicious", "high"].includes(String(value.risk))
    && Array.isArray(value.indicators)
    && value.indicators.length <= STATIC_MALWARE_INDICATORS.size
    && value.indicators.every((indicator) => typeof indicator === "string" && STATIC_MALWARE_INDICATORS.has(indicator))
    && ["full", "sampled"].includes(String(value.coverage));
}

function validAttachmentSecurityInspection(value: unknown): boolean {
  if (!isRecord(value) || !hasExactFields(value, [
    "magicType",
    "extensionMismatch",
    "executableOrScript",
    "macroCapable",
    "archive",
    "staticMalware",
    "incomplete",
    "reasons",
  ])) return false;
  if (!["pe_executable", "elf_executable", "zip", "pdf", "png", "jpeg", "ole_compound", "rtf", "text_or_unknown"].includes(String(value.magicType))) return false;
  if (typeof value.extensionMismatch !== "boolean" || typeof value.executableOrScript !== "boolean" || typeof value.macroCapable !== "boolean" || typeof value.incomplete !== "boolean") return false;
  if (value.archive !== null && !validArchiveSecurityInspection(value.archive)) return false;
  if (!validStaticMalwareInspection(value.staticMalware)) return false;
  return validStringArray(value.reasons, 16, 1_024);
}

function validAttachment(value: unknown): boolean {
  return isRecord(value)
    && hasExactFields(value, ["name", "mimeType", "sizeBytes", "extension", "sha256", "suspiciousNamePattern"], ["securityInspection"])
    && boundedString(value.name, 4_096)
    && boundedString(value.mimeType, 256)
    && Number.isSafeInteger(value.sizeBytes)
    && Number(value.sizeBytes) >= 0
    && Number(value.sizeBytes) <= 2 * 1024 * 1024 * 1024
    && boundedString(value.extension, 256, true)
    && (value.sha256 === null || (typeof value.sha256 === "string" && /^[a-f0-9]{64}$/i.test(value.sha256)))
    && typeof value.suspiciousNamePattern === "boolean"
    && (value.securityInspection === undefined || validAttachmentSecurityInspection(value.securityInspection));
}

function validListHeaders(value: unknown): boolean {
  if (!isRecord(value) || !hasExactFields(value, ["listId", "listUnsubscribe", "listUnsubscribePost"], ["oneClickHeaderSetUnambiguous", "oneClickDkimSignatures"])) return false;
  if (!boundedString(value.listId, 8_192, true) || !boundedString(value.listUnsubscribe, 16_384, true) || !boundedString(value.listUnsubscribePost, 4_096, true)) return false;
  if (value.oneClickHeaderSetUnambiguous !== undefined && typeof value.oneClickHeaderSetUnambiguous !== "boolean") return false;
  if (value.oneClickDkimSignatures === undefined) return true;
  return Array.isArray(value.oneClickDkimSignatures)
    && value.oneClickDkimSignatures.length <= 64
    && value.oneClickDkimSignatures.every((item) => isRecord(item)
      && hasExactFields(item, ["domain", "selector", "coversRequiredHeaders"])
      && boundedString(item.domain, 253)
      && boundedString(item.selector, 253)
      && typeof item.coversRequiredHeaders === "boolean");
}

function validThreadContext(value: unknown): boolean {
  if (!isRecord(value) || !hasExactFields(value, ["isFirstContact", "threadContinuityBroken", "replyToChangedMidThread"], [
    "senderPreviouslySeenInScan",
    "relationshipPriorMessages",
    "relationshipPriorAuthenticatedMessages",
    "relationshipPriorSafeMessages",
    "relationshipPriorSuspiciousMessages",
    "hasEstablishedSenderHistory",
    "relationshipAuthenticationDowngrade",
    "replyToChangedFromRelationshipHistory",
  ])) return false;
  for (const field of [
    "isFirstContact", "threadContinuityBroken", "replyToChangedMidThread", "senderPreviouslySeenInScan",
    "hasEstablishedSenderHistory", "relationshipAuthenticationDowngrade", "replyToChangedFromRelationshipHistory",
  ]) if (value[field] !== undefined && typeof value[field] !== "boolean") return false;
  for (const field of [
    "relationshipPriorMessages", "relationshipPriorAuthenticatedMessages", "relationshipPriorSafeMessages", "relationshipPriorSuspiciousMessages",
  ]) if (value[field] !== undefined && (!Number.isSafeInteger(value[field]) || Number(value[field]) < 0 || Number(value[field]) > 1_000_000)) return false;
  return true;
}

function validCountDiagnostic(value: unknown, fields: string[]): boolean {
  if (!isRecord(value) || !hasExactFields(value, fields)) return false;
  for (const [key, item] of Object.entries(value)) {
    if (key === "incomplete") {
      if (typeof item !== "boolean") return false;
    } else if (key === "incompleteReasons") {
      if (!validStringArray(item, 64, 1_024)) return false;
    } else if (!Number.isSafeInteger(item) || Number(item) < 0 || Number(item) > 10_000) return false;
  }
  return true;
}

function validAttachmentSecurityDiagnostic(value: unknown): boolean {
  return isRecord(value)
    && hasExactFields(value, ["inspected", "incomplete", "encryptedArchives", "resourceLimitedArchives"])
    && validNonNegativeInteger(value.inspected, 10_000)
    && validNonNegativeInteger(value.incomplete, 10_000)
    && validNonNegativeInteger(value.encryptedArchives, 10_000)
    && validNonNegativeInteger(value.resourceLimitedArchives, 10_000);
}

function validDiagnostics(value: unknown): boolean {
  return isRecord(value)
    && hasExactFields(value, ["fetchedAt", "sizeBytes", "encoding", "contentCoverage"], ["qrInspection", "attachmentHashInspection", "attachmentSecurityInspection"])
    && boundedString(value.fetchedAt, 64)
    && Number.isSafeInteger(value.sizeBytes)
    && Number(value.sizeBytes) >= 0
    && Number(value.sizeBytes) <= 128 * 1024 * 1024
    && ["plain", "base64", "quoted-printable", "multipart", "mixed", "unknown"].includes(String(value.encoding))
    && ["complete", "bounded_sufficient", "insufficient"].includes(String(value.contentCoverage))
    && (value.qrInspection === undefined || validCountDiagnostic(value.qrInspection, ["supportedImages", "decodedUrlCount", "incomplete", "incompleteReasons"]))
    && (value.attachmentHashInspection === undefined || validCountDiagnostic(value.attachmentHashInspection, ["attachments", "hashed", "incomplete", "incompleteReasons"]))
    && (value.attachmentSecurityInspection === undefined || validAttachmentSecurityDiagnostic(value.attachmentSecurityInspection));
}

function validEnvelope(value: unknown): value is CanonicalEnvelope {
  if (!isRecord(value) || !hasExactFields(value, ENVELOPE_FIELDS)) return false;
  if (!["gmail", "icloud", "outlook", "yahoo", "imap"].includes(String(value.provider))) return false;
  if (!["inbox", "spam", "sent", "drafts", "trash", "archive", "other"].includes(String(value.folder))) return false;
  if (!boundedString(value.accountProof, 4_096) || !boundedString(value.messageId, 4_096) || !boundedString(value.providerNativeId, 4_096)) return false;
  if (!boundedString(value.providerFolderName, 4_096) || !boundedString(value.subject, 16_384) || !boundedString(value.date, 256)) return false;
  if (!boundedString(value.textPreview, MAX_ENVELOPE_TEXT_CHARS, true)) return false;
  if (!Array.isArray(value.links) || value.links.length > MAX_ENVELOPE_LINKS || !value.links.every(validLink)) return false;
  if (!Array.isArray(value.attachments) || value.attachments.length > MAX_ENVELOPE_ATTACHMENTS || !value.attachments.every(validAttachment)) return false;
  if (!validStringArray(value.parseNotes, MAX_ENVELOPE_NOTES, 4_096)) return false;
  if (!validFromField(value.from) || !validAuthentication(value.authentication) || !validListHeaders(value.listHeaders) || !validThreadContext(value.threadContext) || !validDiagnostics(value.diagnostics)) return false;
  if (value.replyTo !== null && !validFromField(value.replyTo)) return false;
  if (value.htmlSignals !== null) {
    if (!isRecord(value.htmlSignals) || !hasExactFields(value.htmlSignals, ["extractedText", "hrefs", "hasForm", "hasPasswordField"]) || !boundedString(value.htmlSignals.extractedText, MAX_ENVELOPE_TEXT_CHARS, true)) return false;
    if (!validStringArray(value.htmlSignals.hrefs, MAX_ENVELOPE_LINKS, 8_192)) return false;
    if (typeof value.htmlSignals.hasForm !== "boolean" || typeof value.htmlSignals.hasPasswordField !== "boolean") return false;
  }
  if (!["complete", "partial", "malformed", "inaccessible", "skipped"].includes(String(value.parseStatus))) return false;
  return true;
}

export function assertPortableCoreRequest(input: unknown): asserts input is PortableCoreRequestV1 {
  let serialized: string;
  try { serialized = JSON.stringify(input); }
  catch { throw new PortableCoreContractError("invalid_request"); }
  if (new TextEncoder().encode(serialized).length > MAX_PORTABLE_CORE_REQUEST_BYTES) {
    throw new PortableCoreContractError("request_too_large");
  }
  if (
    !isRecord(input)
    || !hasExactFields(input, ["schemaVersion", "envelope", "personalPolicy", "intelligence"])
    || input.schemaVersion !== PORTABLE_CORE_SCHEMA_VERSION
    || !validEnvelope(input.envelope)
    || !validPersonalPolicy(input.personalPolicy)
    || !validIntelligence(input.intelligence)
  ) throw new PortableCoreContractError("invalid_request");
}

export function evaluatePortableCore(input: unknown): PortableCoreResponseV1 {
  assertPortableCoreRequest(input);
  const envelope = structuredClone(input.envelope);
  const personalPolicy = new InMemoryPersonalPolicyStore();
  personalPolicy.restore(structuredClone(input.personalPolicy));
  const entries = input.intelligence.state === "verified" ? structuredClone(input.intelligence.entries) : null;
  const result = scanMessage(envelope, {
    personalPolicy,
    threatFeed: { getVerifiedEntries: () => entries },
  });
  return {
    schemaVersion: PORTABLE_CORE_SCHEMA_VERSION,
    verdict: result.scored.verdict,
    score: result.scored.score,
    confirmedByRule: result.scored.confirmedByRule,
    action: result.action,
    evidence: structuredClone(result.scored.evidence),
    layerResults: structuredClone(result.scored.layerResults),
  };
}

export function scanMessageThroughPortableCore(
  envelope: CanonicalEnvelope,
  personalPolicy: InMemoryPersonalPolicyStore,
  intelligenceEntries: SignedFeedEntry[] | null,
): ScanResult {
  const response = evaluatePortableCore({
    schemaVersion: PORTABLE_CORE_SCHEMA_VERSION,
    envelope,
    personalPolicy: personalPolicy.snapshot(),
    intelligence: intelligenceEntries === null
      ? { state: "unavailable", entries: null }
      : { state: "verified", entries: intelligenceEntries },
  });
  return {
    envelope,
    action: response.action,
    scored: {
      score: response.score,
      evidence: response.evidence,
      verdict: response.verdict,
      confirmedByRule: response.confirmedByRule,
      layerResults: response.layerResults,
    },
  };
}
