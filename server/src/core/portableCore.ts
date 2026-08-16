import type { CanonicalEnvelope, FromField } from "../canonical/envelope.js";
import type { SignedFeedEntry } from "../engine/layers/globalIntelligence.js";
import { InMemoryPersonalPolicyStore } from "../engine/layers/personalRules.js";
import type { ScanResult } from "../engine/pipeline.js";
import { sha256Hex } from "./sha256.js";
import {
  evaluatePortableCore,
  PORTABLE_CORE_SCHEMA_VERSION,
} from "./portableCoreStrict.js";

export {
  MAX_PORTABLE_CORE_REQUEST_BYTES,
  PORTABLE_CORE_SCHEMA_VERSION,
  PortableCoreContractError,
  assertPortableCoreRequest,
  evaluatePortableCore,
} from "./portableCoreStrict.js";
export type {
  PortableCoreRequestV1,
  PortableCoreResponseV1,
  PortableIntelligenceSnapshot,
} from "./portableCoreStrict.js";

const PORTABLE_REDUCED_NOTE = "Portable inspection coverage was reduced because provider data exceeded safety limits.";
const MAX_SUBJECT = 16_384;
const MAX_FROM_TEXT = 4_096;
const MAX_DOMAIN = 253;
const MAX_RAW_AUTH = 16_384;
const MAX_TEXT = 512 * 1024;
const MAX_LINKS = 256;
const MAX_URL = 8_192;
const MAX_LINK_TEXT = 4_096;
const MAX_BRAND = 1_024;
const MAX_ATTACHMENTS = 64;
const MAX_ATTACHMENT_NAME = 4_096;
const MAX_ATTACHMENT_MIME = 256;
const MAX_ATTACHMENT_EXTENSION = 256;
const MAX_ATTACHMENT_BYTES = 2 * 1024 * 1024 * 1024;
const MAX_LIST_ID = 8_192;
const MAX_LIST_UNSUBSCRIBE = 16_384;
const MAX_LIST_UNSUBSCRIBE_POST = 4_096;
const MAX_PARSE_NOTES = 256;
const MAX_NOTE = 4_096;
const MAX_DIAGNOSTIC_REASONS = 64;
const MAX_DIAGNOSTIC_REASON = 1_024;
const MAX_DIAGNOSTIC_COUNT = 10_000;
const MAX_DIAGNOSTIC_BYTES = 128 * 1024 * 1024;

function trimNarrative(value: string, max: number, reduce: () => void): string {
  if (value.length <= max) return value;
  reduce();
  return value.slice(0, max);
}

function trimNullableNarrative(value: string | null, max: number, reduce: () => void): string | null {
  if (value === null) return null;
  return trimNarrative(value, max, reduce);
}

function dropOversized(value: string | null, max: number, reduce: () => void): string | null {
  if (value === null || value.length <= max) return value;
  reduce();
  return null;
}

function sanitizeAddress(field: FromField, reduce: () => void): FromField {
  return {
    displayName: trimNullableNarrative(field.displayName, MAX_FROM_TEXT, reduce),
    address: dropOversized(field.address, MAX_FROM_TEXT, reduce),
    domain: dropOversized(field.domain, MAX_DOMAIN, reduce),
  };
}

function boundedInteger(value: number, max: number, reduce: () => void): number {
  if (Number.isSafeInteger(value) && value >= 0 && value <= max) return value;
  reduce();
  if (!Number.isFinite(value) || value < 0) return 0;
  return Math.min(max, Math.trunc(value));
}

function sanitizeNarrativeArray(values: string[], maxItems: number, maxChars: number, reduce: () => void): string[] {
  if (values.length > maxItems) reduce();
  return values.slice(0, maxItems).map((value) => trimNarrative(value, maxChars, reduce));
}

function sanitizePortableEnvelope(input: CanonicalEnvelope): CanonicalEnvelope {
  const envelope = structuredClone(input);
  let reduced = false;
  const reduce = () => { reduced = true; };

  if (envelope.accountProof.length > MAX_FROM_TEXT) {
    envelope.accountProof = `bounded:${sha256Hex(envelope.accountProof)}`;
    reduce();
  }
  if (envelope.messageId.length > MAX_FROM_TEXT) {
    envelope.messageId = `bounded:${sha256Hex(envelope.messageId)}`;
    reduce();
  }
  if (envelope.providerNativeId.length > MAX_FROM_TEXT) {
    throw new Error("Provider-native message identity exceeded the local safety boundary.");
  }
  envelope.providerFolderName = trimNarrative(envelope.providerFolderName, MAX_FROM_TEXT, reduce);
  envelope.subject = trimNarrative(envelope.subject, MAX_SUBJECT, reduce);
  envelope.date = trimNarrative(envelope.date, 256, reduce);
  envelope.from = sanitizeAddress(envelope.from, reduce);
  if (envelope.replyTo) envelope.replyTo = sanitizeAddress(envelope.replyTo, reduce);

  if (envelope.authentication.rawHeader && envelope.authentication.rawHeader.length > MAX_RAW_AUTH) {
    delete envelope.authentication.rawHeader;
    reduce();
  }

  if (envelope.textPreview !== null) envelope.textPreview = trimNarrative(envelope.textPreview, MAX_TEXT, reduce);
  if (envelope.htmlSignals) {
    if (envelope.htmlSignals.extractedText !== null) {
      envelope.htmlSignals.extractedText = trimNarrative(envelope.htmlSignals.extractedText, MAX_TEXT, reduce);
    }
    const hrefs = envelope.htmlSignals.hrefs.filter((href) => {
      if (href.length <= MAX_URL) return true;
      reduce();
      return false;
    });
    if (hrefs.length > MAX_LINKS) reduce();
    envelope.htmlSignals.hrefs = hrefs.slice(0, MAX_LINKS);
  }

  const safeLinks = envelope.links.filter((link) => {
    if (link.rawUrl.length <= MAX_URL && link.normalizedUrl.length <= MAX_URL) return true;
    reduce();
    return false;
  });
  if (safeLinks.length > MAX_LINKS) reduce();
  envelope.links = safeLinks.slice(0, MAX_LINKS).map((link) => ({
    ...link,
    visibleText: trimNullableNarrative(link.visibleText, MAX_LINK_TEXT, reduce),
    claimedBrand: trimNullableNarrative(link.claimedBrand, MAX_BRAND, reduce),
  }));

  if (envelope.attachments.length > MAX_ATTACHMENTS) reduce();
  envelope.attachments = envelope.attachments.slice(0, MAX_ATTACHMENTS).map((attachment) => {
    const copy = structuredClone(attachment);
    copy.name = trimNarrative(copy.name, MAX_ATTACHMENT_NAME, reduce);
    copy.mimeType = trimNarrative(copy.mimeType, MAX_ATTACHMENT_MIME, reduce);
    copy.extension = dropOversized(copy.extension, MAX_ATTACHMENT_EXTENSION, reduce);
    copy.sizeBytes = boundedInteger(copy.sizeBytes, MAX_ATTACHMENT_BYTES, reduce);
    if (copy.sha256 !== null && !/^[a-f0-9]{64}$/i.test(copy.sha256)) {
      copy.sha256 = null;
      reduce();
    }
    if (copy.securityInspection) {
      copy.securityInspection.reasons = sanitizeNarrativeArray(copy.securityInspection.reasons, 16, MAX_DIAGNOSTIC_REASON, reduce);
      if (copy.securityInspection.archive) {
        const archive = copy.securityInspection.archive;
        archive.entryCount = boundedInteger(archive.entryCount, MAX_DIAGNOSTIC_COUNT, reduce);
        archive.encryptedEntries = boundedInteger(archive.encryptedEntries, MAX_DIAGNOSTIC_COUNT, reduce);
        archive.executableOrScriptEntries = boundedInteger(archive.executableOrScriptEntries, MAX_DIAGNOSTIC_COUNT, reduce);
        archive.macroCapableEntries = boundedInteger(archive.macroCapableEntries, MAX_DIAGNOSTIC_COUNT, reduce);
        archive.nestedArchiveEntries = boundedInteger(archive.nestedArchiveEntries, MAX_DIAGNOSTIC_COUNT, reduce);
        archive.declaredCompressedBytes = boundedInteger(archive.declaredCompressedBytes, Number.MAX_SAFE_INTEGER, reduce);
        archive.declaredUncompressedBytes = boundedInteger(archive.declaredUncompressedBytes, Number.MAX_SAFE_INTEGER, reduce);
        if (!Number.isFinite(archive.maximumCompressionRatio) || archive.maximumCompressionRatio < 0 || archive.maximumCompressionRatio > Number.MAX_SAFE_INTEGER) {
          archive.maximumCompressionRatio = 0;
          reduce();
        }
        archive.reasons = sanitizeNarrativeArray(archive.reasons, 16, MAX_DIAGNOSTIC_REASON, reduce);
      }
    }
    return copy;
  });

  envelope.listHeaders.listId = dropOversized(envelope.listHeaders.listId, MAX_LIST_ID, reduce);
  envelope.listHeaders.listUnsubscribe = dropOversized(envelope.listHeaders.listUnsubscribe, MAX_LIST_UNSUBSCRIBE, reduce);
  envelope.listHeaders.listUnsubscribePost = dropOversized(envelope.listHeaders.listUnsubscribePost, MAX_LIST_UNSUBSCRIBE_POST, reduce);
  if (envelope.listHeaders.oneClickDkimSignatures) {
    const signatures = envelope.listHeaders.oneClickDkimSignatures.filter((signature) => {
      if (signature.domain.length <= MAX_DOMAIN && signature.selector.length <= MAX_DOMAIN) return true;
      reduce();
      return false;
    });
    if (signatures.length > 64) reduce();
    if (signatures.length !== envelope.listHeaders.oneClickDkimSignatures.length) {
      envelope.listHeaders.oneClickHeaderSetUnambiguous = false;
    }
    envelope.listHeaders.oneClickDkimSignatures = signatures.slice(0, 64);
  }

  for (const key of [
    "relationshipPriorMessages",
    "relationshipPriorAuthenticatedMessages",
    "relationshipPriorSafeMessages",
    "relationshipPriorSuspiciousMessages",
  ] as const) {
    const value = envelope.threadContext[key];
    if (value !== undefined) envelope.threadContext[key] = boundedInteger(value, 1_000_000, reduce);
  }

  envelope.diagnostics.fetchedAt = trimNarrative(envelope.diagnostics.fetchedAt, 64, reduce);
  envelope.diagnostics.sizeBytes = boundedInteger(envelope.diagnostics.sizeBytes, MAX_DIAGNOSTIC_BYTES, reduce);
  if (envelope.diagnostics.qrInspection) {
    const diagnostic = envelope.diagnostics.qrInspection;
    diagnostic.supportedImages = boundedInteger(diagnostic.supportedImages, MAX_DIAGNOSTIC_COUNT, reduce);
    diagnostic.decodedUrlCount = boundedInteger(diagnostic.decodedUrlCount, MAX_DIAGNOSTIC_COUNT, reduce);
    diagnostic.incompleteReasons = sanitizeNarrativeArray(diagnostic.incompleteReasons, MAX_DIAGNOSTIC_REASONS, MAX_DIAGNOSTIC_REASON, reduce);
  }
  if (envelope.diagnostics.attachmentHashInspection) {
    const diagnostic = envelope.diagnostics.attachmentHashInspection;
    diagnostic.attachments = boundedInteger(diagnostic.attachments, MAX_DIAGNOSTIC_COUNT, reduce);
    diagnostic.hashed = boundedInteger(diagnostic.hashed, MAX_DIAGNOSTIC_COUNT, reduce);
    diagnostic.incompleteReasons = sanitizeNarrativeArray(diagnostic.incompleteReasons, MAX_DIAGNOSTIC_REASONS, MAX_DIAGNOSTIC_REASON, reduce);
  }
  if (envelope.diagnostics.attachmentSecurityInspection) {
    const diagnostic = envelope.diagnostics.attachmentSecurityInspection;
    diagnostic.inspected = boundedInteger(diagnostic.inspected, MAX_DIAGNOSTIC_COUNT, reduce);
    diagnostic.incomplete = boundedInteger(diagnostic.incomplete, MAX_DIAGNOSTIC_COUNT, reduce);
    diagnostic.encryptedArchives = boundedInteger(diagnostic.encryptedArchives, MAX_DIAGNOSTIC_COUNT, reduce);
    diagnostic.resourceLimitedArchives = boundedInteger(diagnostic.resourceLimitedArchives, MAX_DIAGNOSTIC_COUNT, reduce);
  }

  envelope.parseNotes = sanitizeNarrativeArray(envelope.parseNotes, MAX_PARSE_NOTES, MAX_NOTE, reduce);
  if (reduced) {
    if (envelope.parseStatus === "complete") envelope.parseStatus = "partial";
    envelope.diagnostics.contentCoverage = "insufficient";
    envelope.parseNotes = envelope.parseNotes.filter((note) => note !== PORTABLE_REDUCED_NOTE).slice(0, MAX_PARSE_NOTES - 1);
    envelope.parseNotes.push(PORTABLE_REDUCED_NOTE);
  }

  return envelope;
}

export function scanMessageThroughPortableCore(
  envelope: CanonicalEnvelope,
  personalPolicy: InMemoryPersonalPolicyStore,
  intelligenceEntries: SignedFeedEntry[] | null,
): ScanResult {
  const portableEnvelope = sanitizePortableEnvelope(envelope);
  const response = evaluatePortableCore({
    schemaVersion: PORTABLE_CORE_SCHEMA_VERSION,
    envelope: portableEnvelope,
    personalPolicy: personalPolicy.snapshot(),
    intelligence: intelligenceEntries === null
      ? { state: "unavailable", entries: null }
      : { state: "verified", entries: intelligenceEntries },
  });
  return {
    envelope: portableEnvelope,
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
