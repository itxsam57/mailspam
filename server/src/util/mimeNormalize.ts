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

function parseAuthResultsHeader(raw: string | undefined): AuthenticationSignals {
  const base: AuthenticationSignals = {
    spf: "unknown", dkim: "unknown", dmarc: "unknown", arc: "unknown",
  };
  if (!raw) return base;
  const extract = (name: string): AuthenticationSignals["spf"] => {
    const m = raw.match(new RegExp(`${name}=(\\w+)`, "i"));
    const val = m?.[1]?.toLowerCase();
    if (val === "pass" || val === "fail" || val === "softfail" || val === "neutral" || val === "none") return val;
    return "unknown";
  };
  return {
    spf: extract("spf"),
    dkim: extract("dkim") as AuthenticationSignals["dkim"],
    dmarc: extract("dmarc") as AuthenticationSignals["dmarc"],
    arc: extract("arc") as AuthenticationSignals["arc"],
    rawHeader: raw,
  };
}

function extractLinks(mail: ParsedMail): LinkInfo[] {
  const links: LinkInfo[] = [];
  const html = mail.html || "";
  const anchorRe = /<a\s+[^>]*href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gis;
  let match: RegExpExecArray | null;
  while ((match = anchorRe.exec(html))) {
    const rawUrl = match[1]!;
    const visibleText = match[2]!.replace(/<[^>]+>/g, "").trim() || null;
    let normalizedUrl = rawUrl;
    let claimedBrand: string | null = null;
    let brandDomainMismatch: boolean | null = null;
    try {
      const u = new URL(rawUrl);
      normalizedUrl = u.toString();
      claimedBrand = claimedBrandFromText(visibleText ?? "") ?? claimedBrandFromText(rawUrl);
      if (claimedBrand) {
        const officialDomains = OFFICIAL_BRAND_DOMAINS[claimedBrand]!;
        brandDomainMismatch = !officialDomains.some((d) => u.hostname === d || u.hostname.endsWith(`.${d}`));
      }
    } catch {
      // leave normalizedUrl as raw; link_structure layer will flag MALFORMED_URL
    }
    links.push({ visibleText, rawUrl, normalizedUrl, claimedBrand, brandDomainMismatch });
  }
  // Also pick up bare URLs in plain text for text-only messages.
  if (!html && mail.text) {
    const bareRe = /https?:\/\/[^\s<>"']+/g;
    let m: RegExpExecArray | null;
    while ((m = bareRe.exec(mail.text))) {
      const rawUrl = m[0];
      try {
        const u = new URL(rawUrl);
        links.push({ visibleText: rawUrl, rawUrl, normalizedUrl: u.toString(), claimedBrand: claimedBrandFromText(rawUrl), brandDomainMismatch: null });
      } catch {
        links.push({ visibleText: rawUrl, rawUrl, normalizedUrl: rawUrl, claimedBrand: null, brandDomainMismatch: null });
      }
    }
  }
  return links;
}

function extractAttachments(mail: ParsedMail): AttachmentInfo[] {
  return (mail.attachments ?? []).map((a) => {
    const name = a.filename ?? "unnamed";
    const parts = name.split(".");
    const extension = parts.length > 1 ? parts[parts.length - 1]!.toLowerCase() : null;
    const knownDocLike = new Set(["pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"]);
    const suspiciousNamePattern = parts.length >= 3 && knownDocLike.has(parts[parts.length - 2]!.toLowerCase());
    return {
      name,
      mimeType: a.contentType ?? "application/octet-stream",
      sizeBytes: a.size ?? (a.content ? a.content.length : 0),
      extension,
      sha256: null, // hashed lazily only when safe/needed — never store attachment content
      suspiciousNamePattern,
    };
  });
}

export interface NormalizeOptions {
  provider: Provider;
  accountProof: string;
  providerFolderName: string;
  normalizedFolder: NormalizedFolder;
  /** The provider's own native message id, used for action calls (Trash/move). Required for live adapters; fixtures may pass a synthetic value. */
  providerNativeId: string;
  /** Local mailbox history facts, computed by the caller (never sent anywhere). */
  threadContext?: CanonicalEnvelope["threadContext"];
}

export async function normalizeRawMessage(raw: string | Buffer, opts: NormalizeOptions): Promise<CanonicalEnvelope> {
  let mail: ParsedMail;
  let parseStatus: ParseStatus = "complete";
  const parseNotes: string[] = [];

  try {
    mail = await simpleParser(raw);
  } catch (err) {
    // Even a parser exception must not become a silent skip — surface a
    // malformed envelope with parseStatus reflecting the failure.
    return malformedEnvelope(opts, `MIME parse threw: ${(err as Error).message}`);
  }

  if (!mail.text && !mail.html) {
    parseStatus = "partial";
    parseNotes.push("No text or HTML body could be extracted.");
  }

  const from = firstAddress(mail.from) ?? { displayName: null, address: null, domain: null };
  const replyTo = firstAddress(mail.replyTo);
  const authHeader = mail.headers.get("authentication-results") as string | undefined;

  const textPreview = mail.text ? mail.text.slice(0, TEXT_PREVIEW_MAX_CHARS) : mail.html ? null : null;
  const htmlText = mail.html ? mail.html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, TEXT_PREVIEW_MAX_CHARS) : null;

  const links = extractLinks(mail);
  const attachments = extractAttachments(mail);

  const listHeader = mail.headers.get("list") as
    | { id?: { name?: string }; unsubscribe?: { url?: string }; ["unsubscribe-post"]?: { name?: string } }
    | undefined;
  const listId = listHeader?.id?.name ?? null;
  const listUnsub = listHeader?.unsubscribe?.url ?? null;
  const listUnsubPost = listHeader?.["unsubscribe-post"]?.name ?? null;

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
          hrefs: links.map((l) => l.rawUrl),
          hasForm: /<form[\s>]/i.test(mail.html),
          hasPasswordField: /<input[^>]+type=["']?password/i.test(mail.html),
        }
      : null,
    links,
    attachments,
    listHeaders: { listId, listUnsubscribe: listUnsub, listUnsubscribePost: listUnsubPost },
    threadContext: opts.threadContext ?? { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus,
    parseNotes,
    diagnostics: {
      fetchedAt: new Date().toISOString(),
      sizeBytes: typeof raw === "string" ? Buffer.byteLength(raw) : raw.length,
      encoding: mail.html ? (mail.attachments?.length ? "multipart" : "multipart") : "plain",
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
    diagnostics: { fetchedAt: new Date().toISOString(), sizeBytes: 0, encoding: "unknown" },
  };
}
