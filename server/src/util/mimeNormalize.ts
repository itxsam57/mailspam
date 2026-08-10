import { simpleParser, type ParsedMail, type AddressObject } from "mailparser";
import type {
  CanonicalEnvelope,
  AuthenticationSignals,
  FromField,
  AttachmentInfo,
  NormalizedFolder,
  Provider,
  ParseStatus,
} from "../canonical/envelope.js";
import {
  attachmentSha256,
  MAX_ATTACHMENT_HASH_BYTES,
  MAX_ATTACHMENT_HASHES_PER_MESSAGE,
} from "./attachmentHash.js";
import { analyzeHtmlInteractions, MAX_HTML_INTERACTION_CHARS } from "./htmlInteraction.js";
import { extractOneClickDkimCoverage } from "./dkimSignatureMetadata.js";
import { analyzeQrImages, isSupportedQrImageMimeType } from "./qrDecode.js";

const TEXT_PREVIEW_MAX_CHARS = 4000;
const MAX_THREAD_REFERENCE_IDS = 20;
const MAX_THREAD_MESSAGE_ID_CHARS = 998;
const MAX_THREAD_REFERENCE_HEADER_CHARS = 32 * 1024;

function firstAddress(addr: AddressObject | AddressObject[] | undefined): FromField | null {
  if (!addr) return null;
  const obj = Array.isArray(addr) ? addr[0] : addr;
  const entry = obj?.value?.[0];
  if (!entry) return null;
  const address = entry.address ?? null;
  const domain = address ? address.split("@")[1]?.toLowerCase() ?? null : null;
  return { displayName: entry.name ?? null, address: address?.toLowerCase() ?? null, domain };
}

export function normalizeHeaderText(raw: unknown): string | undefined {
  if (raw === null || raw === undefined) return undefined;
  if (typeof raw === "string") return raw;
  if (Buffer.isBuffer(raw)) return raw.toString("utf8");
  if (Array.isArray(raw)) {
    const parts = raw
      .map((value) => normalizeHeaderText(value))
      .filter((value): value is string => Boolean(value));
    return parts.length ? parts.join("; ") : undefined;
  }
  if (typeof raw === "number" || typeof raw === "boolean" || typeof raw === "bigint") return String(raw);
  if (typeof raw === "object") {
    const record = raw as Record<string, unknown>;
    for (const key of ["value", "text", "name", "url"]) {
      const normalized = normalizeHeaderText(record[key]);
      if (normalized) return normalized;
    }
    const customString = String(raw);
    if (customString && customString !== "[object Object]") return customString;
  }
  return undefined;
}

export function parseAuthResultsHeader(raw: unknown): AuthenticationSignals {
  const base: AuthenticationSignals = {
    spf: "unknown", dkim: "unknown", dmarc: "unknown", arc: "unknown",
  };
  const headerText = normalizeHeaderText(raw);
  if (!headerText) return base;
  const extract = (name: string): AuthenticationSignals["spf"] => {
    const match = headerText.match(new RegExp(`(?:^|[^a-z0-9_-])${name}\\s*=\\s*([\\w-]+)`, "i"));
    const value = match?.[1]?.toLowerCase();
    if (value === "pass" || value === "fail" || value === "softfail" || value === "neutral" || value === "none") return value;
    return "unknown";
  };
  return {
    spf: extract("spf"),
    dkim: extract("dkim") as AuthenticationSignals["dkim"],
    dmarc: extract("dmarc") as AuthenticationSignals["dmarc"],
    arc: extract("arc") as AuthenticationSignals["arc"],
    rawHeader: headerText,
  };
}

/**
 * RFC thread identifiers are accepted only in their explicit <msg-id> form.
 * The input tail, ID count and per-ID length are bounded so a hostile
 * References header cannot become an unbounded Worker/history input. The tail
 * is intentional: RFC reply chains append the direct parent last. Raw values
 * are transient and are HMAC-compared/deleted before scoring.
 */
export function extractThreadMessageIds(raw: unknown): string[] {
  const headerText = normalizeHeaderText(raw);
  if (!headerText) return [];
  const boundedText = headerText.length > MAX_THREAD_REFERENCE_HEADER_CHARS
    ? headerText.slice(-MAX_THREAD_REFERENCE_HEADER_CHARS)
    : headerText;
  const pattern = new RegExp(`<[^<>\\r\\n]{1,${MAX_THREAD_MESSAGE_ID_CHARS - 2}}>`, "g");
  const matches = boundedText.match(pattern) ?? [];
  const newestUnique: string[] = [];
  const seen = new Set<string>();
  for (let index = matches.length - 1; index >= 0 && newestUnique.length < MAX_THREAD_REFERENCE_IDS; index -= 1) {
    const normalized = matches[index]!.trim();
    const key = normalized.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    newestUnique.push(normalized);
  }
  return newestUnique.reverse();
}

function pendingThreadReferences(mail: ParsedMail): CanonicalEnvelope["threadContext"]["pendingThreadReferences"] {
  const inReplyTo = extractThreadMessageIds(mail.headers.get("in-reply-to")).at(-1) ?? null;
  const references = extractThreadMessageIds(mail.headers.get("references"));
  return inReplyTo || references.length > 0 ? { inReplyTo, references } : undefined;
}

function extractAttachments(mail: ParsedMail): AttachmentInfo[] {
  return (mail.attachments ?? []).map((attachment, index) => {
    const name = attachment.filename ?? "unnamed";
    const parts = name.split(".");
    const extension = parts.length > 1 ? parts[parts.length - 1]!.toLowerCase() : null;
    const knownDocLike = new Set(["pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"]);
    const suspiciousNamePattern = parts.length >= 3 && knownDocLike.has(parts[parts.length - 2]!.toLowerCase());
    const content = attachment.content ? Buffer.from(attachment.content) : null;
    const hashEligible = Boolean(
      content &&
      index < MAX_ATTACHMENT_HASHES_PER_MESSAGE &&
      content.length <= MAX_ATTACHMENT_HASH_BYTES,
    );
    return {
      name,
      mimeType: attachment.contentType ?? "application/octet-stream",
      sizeBytes: attachment.size ?? content?.length ?? 0,
      extension,
      sha256: hashEligible ? attachmentSha256(content!) : null,
      suspiciousNamePattern,
    };
  });
}

function attachmentHashInspection(attachments: AttachmentInfo[]): NonNullable<CanonicalEnvelope["diagnostics"]["attachmentHashInspection"]> {
  const hashed = attachments.filter((attachment) => attachment.sha256 !== null).length;
  const incomplete = hashed !== attachments.length;
  const incompleteReasons: string[] = [];
  if (attachments.length > MAX_ATTACHMENT_HASHES_PER_MESSAGE) {
    incompleteReasons.push(`Only the first ${MAX_ATTACHMENT_HASHES_PER_MESSAGE} attachments were eligible for local exact-hash inspection.`);
  }
  if (attachments.slice(0, MAX_ATTACHMENT_HASHES_PER_MESSAGE).some((attachment) => attachment.sizeBytes > MAX_ATTACHMENT_HASH_BYTES)) {
    incompleteReasons.push("One or more attachments exceeded the bounded local exact-hash size limit.");
  }
  if (incomplete && incompleteReasons.length === 0) {
    incompleteReasons.push("One or more complete decoded attachment bodies were unavailable for local exact-hash inspection.");
  }
  return {
    attachments: attachments.length,
    hashed,
    incomplete,
    incompleteReasons,
  };
}

export interface NormalizeOptions {
  provider: Provider;
  accountProof: string;
  providerFolderName: string;
  normalizedFolder: NormalizedFolder;
  providerNativeId: string;
  threadContext?: CanonicalEnvelope["threadContext"];
}

export async function normalizeRawMessage(raw: string | Buffer, opts: NormalizeOptions): Promise<CanonicalEnvelope> {
  let mail: ParsedMail;
  let parseStatus: ParseStatus = "complete";
  const parseNotes: string[] = [];

  try { mail = await simpleParser(raw); }
  catch (error) { return malformedEnvelope(opts, `MIME parse threw: ${(error as Error).message}`); }

  if (!mail.text && !mail.html) {
    parseStatus = "partial";
    parseNotes.push("No text or HTML body could be extracted.");
  }

  const from = firstAddress(mail.from) ?? { displayName: null, address: null, domain: null };
  const replyTo = firstAddress(mail.replyTo);
  const authHeader = mail.headers.get("authentication-results");
  const textPreview = mail.text ? mail.text.slice(0, TEXT_PREVIEW_MAX_CHARS) : null;
  const htmlSource = typeof mail.html === "string"
    ? mail.html.slice(0, MAX_HTML_INTERACTION_CHARS)
    : "";
  const htmlText = htmlSource
    ? htmlSource.replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, TEXT_PREVIEW_MAX_CHARS)
    : null;

  const htmlAnalysis = analyzeHtmlInteractions(mail.html, mail.text);
  if (htmlAnalysis.incomplete) {
    parseStatus = "partial";
    parseNotes.push(...htmlAnalysis.incompleteReasons);
  }
  const links = [...htmlAnalysis.links];
  const attachments = extractAttachments(mail);
  const qrInputs = (mail.attachments ?? [])
    .filter((attachment) => isSupportedQrImageMimeType(attachment.contentType ?? ""))
    .map((attachment) => ({
      name: attachment.filename ?? "unnamed-image",
      mimeType: attachment.contentType ?? "application/octet-stream",
      content: Buffer.from(attachment.content),
    }));
  const qrAnalysis = analyzeQrImages(qrInputs);
  links.push(...qrAnalysis.links);
  parseNotes.push(...qrAnalysis.incompleteReasons);

  const listHeader = mail.headers.get("list") as
    | { id?: { name?: string }; unsubscribe?: { url?: string }; ["unsubscribe-post"]?: { name?: string } }
    | undefined;
  const listId = listHeader?.id?.name ?? normalizeHeaderText(mail.headers.get("list-id")) ?? null;
  const listUnsubscribe = listHeader?.unsubscribe?.url ?? normalizeHeaderText(mail.headers.get("list-unsubscribe")) ?? null;
  const listUnsubscribePost = listHeader?.["unsubscribe-post"]?.name ?? normalizeHeaderText(mail.headers.get("list-unsubscribe-post")) ?? null;
  const threadContext: CanonicalEnvelope["threadContext"] = opts.threadContext
    ? { ...opts.threadContext }
    : { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false };
  const pendingReferences = pendingThreadReferences(mail);
  if (pendingReferences) threadContext.pendingThreadReferences = pendingReferences;

  return {
    provider: opts.provider,
    accountProof: opts.accountProof,
    messageId: mail.messageId ?? `generated-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    providerNativeId: opts.providerNativeId,
    folder: opts.normalizedFolder,
    providerFolderName: opts.providerFolderName,
    from,
    replyTo,
    subject: mail.subject ?? "",
    date: (mail.date ?? new Date()).toISOString(),
    authentication: parseAuthResultsHeader(authHeader),
    textPreview,
    htmlSignals: mail.html
      ? {
          extractedText: htmlText,
          hrefs: [...htmlAnalysis.htmlHrefs],
          hasForm: htmlAnalysis.hasForm,
          hasPasswordField: htmlAnalysis.hasPasswordField,
        }
      : null,
    links,
    attachments,
    listHeaders: {
      listId,
      listUnsubscribe,
      listUnsubscribePost,
      oneClickDkimCoverage: extractOneClickDkimCoverage(raw),
    },
    threadContext,
    parseStatus,
    parseNotes,
    diagnostics: {
      fetchedAt: new Date().toISOString(),
      sizeBytes: typeof raw === "string" ? Buffer.byteLength(raw) : raw.length,
      encoding: mail.html ? "multipart" : "plain",
      contentCoverage: parseStatus === "complete" ? "complete" : "insufficient",
      qrInspection: {
        supportedImages: qrInputs.length,
        decodedUrlCount: qrAnalysis.links.length,
        incomplete: qrAnalysis.incomplete,
        incompleteReasons: [...qrAnalysis.incompleteReasons],
      },
      attachmentHashInspection: attachmentHashInspection(attachments),
    },
  };
}

function malformedEnvelope(opts: NormalizeOptions, reason: string): CanonicalEnvelope {
  return {
    provider: opts.provider,
    accountProof: opts.accountProof,
    messageId: `malformed-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    providerNativeId: opts.providerNativeId,
    folder: opts.normalizedFolder,
    providerFolderName: opts.providerFolderName,
    from: { displayName: null, address: null, domain: null },
    replyTo: null,
    subject: "",
    date: new Date().toISOString(),
    authentication: { spf: "unknown", dkim: "unknown", dmarc: "unknown", arc: "unknown" },
    textPreview: null,
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "malformed",
    parseNotes: [reason],
    diagnostics: {
      fetchedAt: new Date().toISOString(),
      sizeBytes: 0,
      encoding: "unknown",
      contentCoverage: "insufficient",
      qrInspection: { supportedImages: 0, decodedUrlCount: 0, incomplete: false, incompleteReasons: [] },
      attachmentHashInspection: { attachments: 0, hashed: 0, incomplete: false, incompleteReasons: [] },
    },
  };
}
