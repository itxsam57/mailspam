import { createHash } from "node:crypto";
import { simpleParser } from "mailparser";
import type { AttachmentInfo } from "../../canonical/envelope.js";
import { isSupportedQrImageMimeType } from "../../util/qrDecode.js";

export interface ImapBodyNode {
  part?: string;
  type?: string;
  size?: number;
  disposition?: string;
  encoding?: string;
  parameters?: Record<string, unknown>;
  dispositionParameters?: Record<string, unknown>;
  childNodes?: ImapBodyNode[];
}

export interface ReadableTextPart {
  part: string;
  contentType: "text/plain" | "text/html";
  sizeBytes: number | null;
  charset: string | null;
  transferEncoding: string | null;
}

export interface QrImagePart {
  part: string;
  name: string;
  mimeType: "image/png" | "image/jpeg";
  sizeBytes: number | null;
  transferEncoding: string | null;
}

export interface HashableAttachmentPart {
  part: string;
  attachmentIndex: number;
  name: string;
  mimeType: string;
  sizeBytes: number | null;
  transferEncoding: string | null;
}

export interface ReadablePartSelection {
  /** Legacy convenience fields retained for existing callers/tests. */
  plainPart: string | null;
  htmlPart: string | null;
  plain: ReadableTextPart | null;
  html: ReadableTextPart | null;
  attachments: AttachmentInfo[];
  /** Complete attachment MIME parts eligible for bounded local exact hashing. */
  hashableAttachments: HashableAttachmentPart[];
  /** Supported image parts only; their bytes are fetched separately under QR limits. */
  qrImages: QrImagePart[];
}

export interface DecodedTextPart {
  text: string;
  decodedLength: number;
  truncated: boolean;
}

function parameterText(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function finiteSize(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

function attachmentInfo(node: ImapBodyNode): AttachmentInfo | null {
  const type = (node.type ?? "application/octet-stream").toLowerCase();
  const topType = type.split("/")[0];
  const disposition = (node.disposition ?? "").toLowerCase();
  const explicitName =
    parameterText(node.dispositionParameters?.filename) ??
    parameterText(node.parameters?.name);
  const isAttachment = topType !== "multipart" && (
    disposition === "attachment" ||
    topType !== "text" ||
    (disposition === "inline" && Boolean(explicitName))
  );

  if (!isAttachment) return null;

  const name = explicitName ?? "unnamed";
  const pieces = name.split(".");
  const extension = pieces.length > 1 ? pieces[pieces.length - 1]!.toLowerCase() : null;
  const documentLike = new Set(["pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"]);
  const suspiciousNamePattern = pieces.length >= 3 && documentLike.has(pieces[pieces.length - 2]!.toLowerCase());
  const sizeBytes = finiteSize(node.size) ?? 0;

  return {
    name,
    mimeType: type,
    sizeBytes,
    extension,
    sha256: null,
    suspiciousNamePattern,
  };
}

function hashableAttachmentPart(
  node: ImapBodyNode,
  attachmentIndex: number,
  attachment: AttachmentInfo,
  isRoot: boolean,
): HashableAttachmentPart | null {
  const part = parameterText(node.part) ?? (isRoot && !node.childNodes?.length ? "TEXT" : null);
  if (!part) return null;
  return {
    part,
    attachmentIndex,
    name: attachment.name,
    mimeType: attachment.mimeType,
    sizeBytes: finiteSize(node.size),
    transferEncoding: parameterText(node.encoding)?.toLowerCase() ?? null,
  };
}

function readablePart(node: ImapBodyNode, isRoot: boolean): ReadableTextPart | null {
  const contentType = (node.type ?? "").toLowerCase();
  if (contentType !== "text/plain" && contentType !== "text/html") return null;

  const part = parameterText(node.part) ?? (isRoot && !node.childNodes?.length ? "TEXT" : null);
  if (!part) return null;

  return {
    part,
    contentType,
    sizeBytes: finiteSize(node.size),
    charset: parameterText(node.parameters?.charset),
    transferEncoding: parameterText(node.encoding)?.toLowerCase() ?? null,
  };
}

function qrImagePart(node: ImapBodyNode, isRoot: boolean): QrImagePart | null {
  const mimeType = (node.type ?? "").toLowerCase();
  if (!isSupportedQrImageMimeType(mimeType)) return null;
  const part = parameterText(node.part) ?? (isRoot && !node.childNodes?.length ? "TEXT" : null);
  if (!part) return null;
  return {
    part,
    name:
      parameterText(node.dispositionParameters?.filename) ??
      parameterText(node.parameters?.name) ??
      `image-${part.replace(/[^a-z0-9_.-]/gi, "-")}`,
    mimeType,
    sizeBytes: finiteSize(node.size),
    transferEncoding: parameterText(node.encoding)?.toLowerCase() ?? null,
  };
}

export function inspectBodyStructure(root: ImapBodyNode | null | undefined): ReadablePartSelection {
  const selected: { plain: ReadableTextPart | null; html: ReadableTextPart | null } = {
    plain: null,
    html: null,
  };
  const attachments: AttachmentInfo[] = [];
  const hashableAttachments: HashableAttachmentPart[] = [];
  const qrImages: QrImagePart[] = [];

  const visit = (node: ImapBodyNode, insideAttachment: boolean, isRoot: boolean) => {
    const attachment = attachmentInfo(node);
    const branchIsAttachment = insideAttachment || attachment !== null;
    const candidate = !branchIsAttachment ? readablePart(node, isRoot) : null;

    if (candidate?.contentType === "text/plain" && !selected.plain) selected.plain = candidate;
    if (candidate?.contentType === "text/html" && !selected.html) selected.html = candidate;

    if (attachment) {
      const attachmentIndex = attachments.length;
      attachments.push(attachment);
      const hashPart = hashableAttachmentPart(node, attachmentIndex, attachment, isRoot);
      if (hashPart) hashableAttachments.push(hashPart);
    }
    const qrCandidate = qrImagePart(node, isRoot);
    if (qrCandidate) qrImages.push(qrCandidate);

    for (const child of node.childNodes ?? []) visit(child, branchIsAttachment, false);
  };

  if (root) visit(root, false, true);
  return {
    plainPart: selected.plain?.part ?? null,
    htmlPart: selected.html?.part ?? null,
    plain: selected.plain,
    html: selected.html,
    attachments,
    hashableAttachments,
    qrImages,
  };
}

function splitHeaderBlocks(rawHeaders: string): string[] {
  const normalized = rawHeaders.replace(/\r?\n/g, "\n");
  const blocks: string[] = [];
  let current = "";

  for (const line of normalized.split("\n")) {
    if (/^[ \t]/.test(line) && current) {
      current += `\r\n${line}`;
      continue;
    }
    if (current) blocks.push(current);
    current = line;
  }
  if (current) blocks.push(current);
  return blocks;
}

function filteredMessageHeaders(headers: Buffer | string): string {
  const headerText = Buffer.isBuffer(headers) ? headers.toString("utf8") : headers;
  return splitHeaderBlocks(headerText)
    .filter((block) => {
      const name = block.split(":", 1)[0]?.trim().toLowerCase();
      return !["content-type", "content-transfer-encoding", "content-disposition", "mime-version"].includes(name ?? "");
    })
    .join("\r\n");
}

function singlePartRaw(params: {
  headers: Buffer | string;
  body: string;
  contentType: "text/plain" | "text/html";
}): Buffer {
  const raw = [
    filteredMessageHeaders(params.headers),
    "MIME-Version: 1.0",
    `Content-Type: ${params.contentType}; charset=utf-8`,
    "Content-Transfer-Encoding: 8bit",
    "",
    params.body,
  ].join("\r\n");
  return Buffer.from(raw, "utf8");
}

export function buildSyntheticRawMessage(params: {
  headers: Buffer | string;
  body: string;
  contentType: "text/plain" | "text/html";
}): Buffer {
  return singlePartRaw(params);
}

/**
 * Reconstructs only the bounded decoded readable alternatives. This preserves
 * both visible text and HTML href destinations without copying attachment
 * bodies or the complete provider message source.
 */
export function buildSyntheticReadableMessage(params: {
  headers: Buffer | string;
  plainBody?: string | null;
  htmlBody?: string | null;
}): Buffer {
  const plainBody = params.plainBody?.trim() ? params.plainBody : null;
  const htmlBody = params.htmlBody?.trim() ? params.htmlBody : null;

  if (!plainBody && !htmlBody) {
    return singlePartRaw({ headers: params.headers, body: "", contentType: "text/plain" });
  }
  if (!plainBody || !htmlBody) {
    return singlePartRaw({
      headers: params.headers,
      body: plainBody ?? htmlBody ?? "",
      contentType: plainBody ? "text/plain" : "text/html",
    });
  }

  let boundary = `email-shield-${createHash("sha256")
    .update(plainBody)
    .update("\0")
    .update(htmlBody)
    .digest("hex")
    .slice(0, 24)}`;
  while (plainBody.includes(boundary) || htmlBody.includes(boundary)) boundary += "x";

  const raw = [
    filteredMessageHeaders(params.headers),
    "MIME-Version: 1.0",
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    "",
    `--${boundary}`,
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: 8bit",
    "",
    plainBody,
    `--${boundary}`,
    "Content-Type: text/html; charset=utf-8",
    "Content-Transfer-Encoding: 8bit",
    "",
    htmlBody,
    `--${boundary}--`,
    "",
  ].join("\r\n");

  return Buffer.from(raw, "utf8");
}

function safeHeaderToken(value: string | null): string | null {
  if (!value) return null;
  const normalized = value.replace(/[\r\n";]/g, "").trim();
  return normalized || null;
}

/** Decode one bounded raw IMAP body part using its BODYSTRUCTURE metadata. */
export async function decodeFetchedTextPart(
  rawPart: Buffer,
  part: ReadableTextPart,
  maxDecodedChars: number,
): Promise<DecodedTextPart> {
  const charset = safeHeaderToken(part.charset);
  const transferEncoding = safeHeaderToken(part.transferEncoding);
  const headers = [
    `Content-Type: ${part.contentType}${charset ? `; charset="${charset}"` : ""}`,
    ...(transferEncoding ? [`Content-Transfer-Encoding: ${transferEncoding}`] : []),
    "MIME-Version: 1.0",
    "",
  ].join("\r\n") + "\r\n";
  const parsed = await simpleParser(Buffer.concat([Buffer.from(headers, "utf8"), rawPart]));
  const decoded = part.contentType === "text/html"
    ? (typeof parsed.html === "string" ? parsed.html : parsed.text ?? "")
    : (parsed.text ?? (typeof parsed.html === "string" ? parsed.html : ""));
  const decodedLength = decoded.length;
  return {
    text: decoded.slice(0, maxDecodedChars),
    decodedLength,
    truncated: decodedLength > maxDecodedChars,
  };
}

async function decodeFetchedBinaryPart(
  rawPart: Buffer,
  part: { name: string; mimeType: string; transferEncoding: string | null },
): Promise<Buffer> {
  const transferEncoding = safeHeaderToken(part.transferEncoding);
  const safeName = part.name.replace(/[\r\n";]/g, "").slice(0, 160) || "attachment";
  const safeMimeType = part.mimeType.replace(/[\r\n";]/g, "").trim().toLowerCase() || "application/octet-stream";
  const headers = [
    `Content-Type: ${safeMimeType}; name="${safeName}"`,
    `Content-Disposition: attachment; filename="${safeName}"`,
    ...(transferEncoding ? [`Content-Transfer-Encoding: ${transferEncoding}`] : []),
    "MIME-Version: 1.0",
    "",
  ].join("\r\n") + "\r\n";
  const parsed = await simpleParser(Buffer.concat([Buffer.from(headers, "utf8"), rawPart]));
  const attachment = parsed.attachments?.[0];
  if (!attachment?.content) throw new Error("The MIME body part did not decode to attachment bytes.");
  return Buffer.from(attachment.content);
}

function assertCompleteFetchedBinaryPart(rawPart: Buffer, expectedBytes: number | null): void {
  if (expectedBytes !== null && rawPart.length < expectedBytes) {
    throw new Error("The provider returned fewer MIME-part bytes than declared by BODYSTRUCTURE.");
  }
}

/** Decode one bounded PNG/JPEG IMAP body part without retaining it afterward. */
export async function decodeFetchedQrImagePart(rawPart: Buffer, part: QrImagePart): Promise<Buffer> {
  assertCompleteFetchedBinaryPart(rawPart, part.sizeBytes);
  return decodeFetchedBinaryPart(rawPart, part);
}

/**
 * Decode one bounded generic IMAP attachment part for local exact hashing.
 * BODYSTRUCTURE provides the expected body octet count. A shorter provider
 * response is incomplete and must never become a valid hash of only a prefix.
 */
export async function decodeFetchedAttachmentPart(rawPart: Buffer, part: HashableAttachmentPart): Promise<Buffer> {
  assertCompleteFetchedBinaryPart(rawPart, part.sizeBytes);
  return decodeFetchedBinaryPart(rawPart, part);
}

/**
 * Truncation is determined from the selected MIME part and the actual bounded
 * fetch. The whole RFC822 message size must never be used for this decision.
 */
export function boundedTextPartWasTruncated(params: {
  declaredPartBytes: number | null;
  fetchedRawBytes: number;
  decodedChars: number;
  rawByteLimit: number;
  decodedCharLimit: number;
}): boolean {
  return params.decodedChars > params.decodedCharLimit ||
    params.fetchedRawBytes >= params.rawByteLimit ||
    (params.declaredPartBytes !== null && params.declaredPartBytes > params.fetchedRawBytes);
}

export function decodeTextBuffer(buffer: Buffer, charset: unknown): string {
  const label = typeof charset === "string" && charset.trim() ? charset.trim().toLowerCase() : "utf-8";
  try {
    return new TextDecoder(label).decode(buffer);
  } catch {
    return buffer.toString("utf8");
  }
}
