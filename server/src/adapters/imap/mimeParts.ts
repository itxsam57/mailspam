import type { AttachmentInfo } from "../../canonical/envelope.js";

export interface ImapBodyNode {
  part?: string;
  type?: string;
  size?: number;
  disposition?: string;
  parameters?: Record<string, unknown>;
  dispositionParameters?: Record<string, unknown>;
  childNodes?: ImapBodyNode[];
}

export interface ReadablePartSelection {
  plainPart: string | null;
  htmlPart: string | null;
  attachments: AttachmentInfo[];
}

function parameterText(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
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
  const extension = pieces.length > 1 ? pieces.at(-1)!.toLowerCase() : null;
  const documentLike = new Set(["pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"]);
  const suspiciousNamePattern = pieces.length >= 3 && documentLike.has(pieces.at(-2)!.toLowerCase());

  return {
    name,
    mimeType: type,
    sizeBytes: Number.isFinite(node.size) ? Number(node.size) : 0,
    extension,
    sha256: null,
    suspiciousNamePattern,
  };
}

export function inspectBodyStructure(root: ImapBodyNode | null | undefined): ReadablePartSelection {
  let plainPart: string | null = null;
  let htmlPart: string | null = null;
  const attachments: AttachmentInfo[] = [];

  const visit = (node: ImapBodyNode) => {
    const type = (node.type ?? "").toLowerCase();
    const disposition = (node.disposition ?? "").toLowerCase();
    const readableInlineText = disposition !== "attachment";
    const part = node.part ?? "1";

    if (readableInlineText && type === "text/plain" && !plainPart) plainPart = part;
    if (readableInlineText && type === "text/html" && !htmlPart) htmlPart = part;

    const attachment = attachmentInfo(node);
    if (attachment) attachments.push(attachment);

    for (const child of node.childNodes ?? []) visit(child);
  };

  if (root) visit(root);
  return { plainPart, htmlPart, attachments };
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

export function buildSyntheticRawMessage(params: {
  headers: Buffer | string;
  body: string;
  contentType: "text/plain" | "text/html";
}): Buffer {
  const headerText = Buffer.isBuffer(params.headers) ? params.headers.toString("utf8") : params.headers;
  const filteredHeaders = splitHeaderBlocks(headerText)
    .filter((block) => {
      const name = block.split(":", 1)[0]?.trim().toLowerCase();
      return !["content-type", "content-transfer-encoding", "content-disposition", "mime-version"].includes(name ?? "");
    })
    .join("\r\n");

  const raw = [
    filteredHeaders,
    "MIME-Version: 1.0",
    `Content-Type: ${params.contentType}; charset=utf-8`,
    "Content-Transfer-Encoding: 8bit",
    "",
    params.body,
  ].join("\r\n");

  return Buffer.from(raw, "utf8");
}

export function decodeTextBuffer(buffer: Buffer, charset: unknown): string {
  const label = typeof charset === "string" && charset.trim() ? charset.trim().toLowerCase() : "utf-8";
  try {
    return new TextDecoder(label).decode(buffer);
  } catch {
    return buffer.toString("utf8");
  }
}
