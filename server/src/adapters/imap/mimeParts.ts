import { createHash } from "node:crypto";
import { simpleParser } from "mailparser";
import type { AttachmentInfo } from "../../canonical/envelope.js";

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

export interface ReadablePartSelection {
  /** Legacy convenience fields retained for existing callers/tests. */
  plainPart: string | null;
  htmlPart: string | null;
  plain: ReadableTextPart | null;
  html: ReadableTextPart | null;
  attachments: AttachmentInfo[];
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
  const isAttachment =
    disposition === "attachment" ||
    (topType !== "text" && topType !== "multipart" && disposition !== "inline");

  if (!isAttachment) return null;

  const name =
    parameterText(node.dispositionParameters?.filename) ??
    parameterText(node.parameters?.name) ??
    "unnamed";
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

function readablePart(node: ImapBodyNode, isRoot: boolean): ReadableTextPart | null {
  const contentType = (node.type ?? "").toLowerCase();
  if (contentType !== "text/plain" && contentType !== "text/html") return null;

  // ImapFlow addresses a single-node message body as TEXT. Using the former
  // fallback of "1" caused an extra BODYSTRUCTURE command for every such
  // message before the body could be downloaded.
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

export function inspectBodyStructure(root: ImapBodyNode | null | undefined): ReadablePartSelection {
  let plain: ReadableTextPart | null = null;
  let html: ReadableTextPart | null = null;
  const attachments: AttachmentInfo[] = [];

  const visit = (node: ImapBodyNode, insideAttachment: boolean, isRoot: boolean) => {
    const disposition = (node.disposition ?? "").toLowerCase();
    const branchIsAttachment = insideAttachment || disposition === "attachment";
    const candidate = !branchIsAttachment ? readablePart(node, isRoot) : null;

    if (candidate?.contentType === "text/plain" && !plain) plain = candidate;
    if (candidate?.contentType === "text/html" && !html) html = candidate;

    const attachment = attachmentInfo(node);
    if (attachment) attachments.push(attachment);

    for (const child of node.childNodes ?? []) visit(child, branchIsAttachment, false);
  };

  if (root) visit(root, false, true);
  return {
    plainPart: plain?.part ?? null,
    htmlPart: html?.part ?? null,
    plain,
    html,
    attachments,
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
  ].join("\r\n");
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
