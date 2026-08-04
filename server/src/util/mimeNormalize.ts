import { simpleParser, type ParsedMail, type AddressObject } from "mailparser";
import type {
  CanonicalEnvelope,
  AuthenticationSignals,
  FromField,
  LinkInfo,
  AttachmentInfo,
  NormalizedFolder,
  Provider,
  ParseStatus,
} from "../canonical/envelope.js";
import { OFFICIAL_BRAND_DOMAINS, claimedBrandFromText } from "../engine/layers/identityImpersonation.js";

const TEXT_PREVIEW_MAX_CHARS = 4000;

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

function urlCandidate(raw: string): string {
  const trimmed = raw.trim();
  if (/^www\./i.test(trimmed)) return `https://${trimmed}`;
  if (/^\/\//.test(trimmed)) return `https:${trimmed}`;
  return trimmed;
}

function extractLinks(mail: ParsedMail): LinkInfo[] {
  const links: LinkInfo[] = [];
  const html = mail.html || "";
  const anchorRe = /<a\s+[^>]*href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gis;
  let match: RegExpExecArray | null;
  while ((match = anchorRe.exec(html))) {
    const originalRawUrl = match[1]!;
    const rawUrl = urlCandidate(originalRawUrl);
    const visibleText = match[2]!.replace(/<[^>]+>/g, "").replace(/&nbsp;/gi, " ").trim() || null;
    let normalizedUrl = rawUrl;
    let claimedBrand: string | null = null;
    let brandDomainMismatch: boolean | null = null;
    try {
      const url = new URL(rawUrl);
      normalizedUrl = url.toString();
      claimedBrand = claimedBrandFromText(visibleText ?? "") ?? claimedBrandFromText(rawUrl);
      if (claimedBrand) {
        const officialDomains = OFFICIAL_BRAND_DOMAINS[claimedBrand]!;
        brandDomainMismatch = !officialDomains.some(
          (domain) => url.hostname === domain || url.hostname.endsWith(`.${domain}`),
        );
      }
    } catch {
      // link_structure layer will report truly malformed values.
    }
    links.push({ visibleText, rawUrl, normalizedUrl, claimedBrand, brandDomainMismatch });
  }
  if (!html && mail.text) {
    const bareRe = /(?:https?:\/\/|www\.)[^\s<>"']+/gi;
    let bare: RegExpExecArray | null;
    while ((bare = bareRe.exec(mail.text))) {
      const rawUrl = urlCandidate(bare[0]);
      try {
        const url = new URL(rawUrl);
        links.push({
          visibleText: bare[0],
          rawUrl,
          normalizedUrl: url.toString(),
          claimedBrand: claimedBrandFromText(rawUrl),
          brandDomainMismatch: null,
        });
      } catch {
        links.push({ visibleText: bare[0], rawUrl, normalizedUrl: rawUrl, claimedBrand: null, brandDomainMismatch: null });
      }
    }
  }
  return links;
}

function extractAttachments(mail: ParsedMail): AttachmentInfo[] {
  return (mail.attachments ?? []).map((attachment) => {
    const name = attachment.filename ?? "unnamed";
    const parts = name.split(".");
    const extension = parts.length > 1 ? parts[parts.length - 1]!.toLowerCase() : null;
    const knownDocLike = new Set(["pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"]);
    const suspiciousNamePattern = parts.length >= 3 && knownDocLike.has(parts[parts.length - 2]!.toLowerCase());
    return {
      name,
      mimeType: attachment.contentType ?? "application/octet-stream",
      sizeBytes: attachment.size ?? (attachment.content ? attachment.content.length : 0),
      extension,
      sha256: null,
      suspiciousNamePattern,
    };
  });
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

  try {
    mail = await simpleParser(raw);
  } catch (error) {
    return malformedEnvelope(opts, `MIME parse threw: ${(error as Error).message}`);
  }

  if (!mail.text && !mail.html) {
    parseStatus = "partial";
    parseNotes.push("No text or HTML body could be extracted.");
  }

  const from = firstAddress(mail.from) ?? { displayName: null, address: null, domain: null };
  const replyTo = firstAddress(mail.replyTo);
  const authHeader = mail.headers.get("authentication-results");
  const textPreview = mail.text ? mail.text.slice(0, TEXT_PREVIEW_MAX_CHARS) : null;
  const htmlText = mail.html
    ? mail.html.replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, TEXT_PREVIEW_MAX_CHARS)
    : null;

  const links = extractLinks(mail);
  const attachments = extractAttachments(mail);

  const listHeader = mail.headers.get("list") as
    | { id?: { name?: string }; unsubscribe?: { url?: string }; ["unsubscribe-post"]?: { name?: string } }
    | undefined;
  const listId = listHeader?.id?.name ?? normalizeHeaderText(mail.headers.get("list-id")) ?? null;
  const listUnsubscribe =
    listHeader?.unsubscribe?.url ??
    normalizeHeaderText(mail.headers.get("list-unsubscribe")) ??
    null;
  const listUnsubscribePost =
    listHeader?.["unsubscribe-post"]?.name ??
    normalizeHeaderText(mail.headers.get("list-unsubscribe-post")) ??
    null;

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
          hrefs: links.map((link) => link.rawUrl),
          hasForm: /<form[\s>]/i.test(mail.html),
          hasPasswordField: /<input[^>]+type=["']?password/i.test(mail.html),
        }
      : null,
    links,
    attachments,
    listHeaders: { listId, listUnsubscribe, listUnsubscribePost },
    threadContext: opts.threadContext ?? { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus,
    parseNotes,
    diagnostics: {
      fetchedAt: new Date().toISOString(),
      sizeBytes: typeof raw === "string" ? Buffer.byteLength(raw) : raw.length,
      encoding: mail.html ? "multipart" : "plain",
      contentCoverage: parseStatus === "complete" ? "complete" : "insufficient",
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
    },
  };
}
