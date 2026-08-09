import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import type { LayerResult } from "../verdict.js";

const DANGEROUS_EXTENSIONS = new Set([
  "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse",
  "wsf", "wsh", "msi", "msp", "hta", "jar", "ps1", "psm1", "reg", "cpl",
  "dll", "iso", "img", "vhd", "lnk",
]);

const MACRO_ENABLED_EXTENSIONS = new Set(["docm", "xlsm", "pptm", "dotm", "xltm"]);
const ARCHIVE_EXTENSIONS = new Set(["zip", "rar", "7z", "iso", "img", "cab"]);

/**
 * Media types are sender-supplied metadata, so they are risk evidence rather
 * than proof of file contents. They matter when a dangerous payload is renamed
 * to a harmless-looking extension, which the former filename-only layer missed.
 */
const DANGEROUS_MEDIA_TYPES = new Set([
  "application/vnd.microsoft.portable-executable",
  "application/x-dosexec",
  "application/x-msdownload",
  "application/x-msdos-program",
  "application/x-executable",
  "application/x-pie-executable",
  "application/x-sharedlib",
  "application/java-archive",
  "application/x-java-archive",
  "application/javascript",
  "application/x-javascript",
  "text/javascript",
  "application/x-sh",
  "application/x-shellscript",
  "text/x-shellscript",
]);

const MACRO_ENABLED_MEDIA_TYPES = new Set([
  "application/vnd.ms-word.document.macroenabled.12",
  "application/vnd.ms-word.template.macroenabled.12",
  "application/vnd.ms-excel.sheet.macroenabled.12",
  "application/vnd.ms-excel.template.macroenabled.12",
  "application/vnd.ms-excel.addin.macroenabled.12",
  "application/vnd.ms-powerpoint.presentation.macroenabled.12",
  "application/vnd.ms-powerpoint.slideshow.macroenabled.12",
  "application/vnd.ms-powerpoint.template.macroenabled.12",
  "application/vnd.ms-powerpoint.addin.macroenabled.12",
]);

const ARCHIVE_MEDIA_TYPES = new Set([
  "application/zip",
  "application/x-7z-compressed",
  "application/vnd.rar",
  "application/x-rar-compressed",
  "application/vnd.ms-cab-compressed",
  "application/x-iso9660-image",
]);

const BIDI_FILENAME_CONTROL = /[\u202a-\u202e\u2066-\u2069]/u;

function normalizedFilename(name: string): string {
  return name
    .normalize("NFKC")
    .replace(/[\u202a-\u202e\u2066-\u2069]/gu, "")
    .trim();
}

function extOf(name: string): string {
  const parts = normalizedFilename(name).split(".");
  return parts.length > 1 ? parts[parts.length - 1]!.trim().toLowerCase() : "";
}

function mediaTypeOf(raw: string): string {
  return raw.split(";", 1)[0]!.trim().toLowerCase();
}

/** invoice.pdf.exe — more than one extension-like segment before the true extension. */
function hasDoubleExtension(name: string): boolean {
  const parts = normalizedFilename(name).split(".");
  if (parts.length < 3) return false;
  const knownDocLike = new Set(["pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"]);
  return knownDocLike.has(parts[parts.length - 2]!.trim().toLowerCase());
}

export function attachmentQrLayer(envelope: CanonicalEnvelope): LayerResult {
  const evidence: LayerResult["evidence"] = [];

  for (const att of envelope.attachments) {
    const ext = extOf(att.name) || att.extension?.trim().toLowerCase() || "";
    const mediaType = mediaTypeOf(att.mimeType);
    const dangerousExtension = DANGEROUS_EXTENSIONS.has(ext);
    const macroExtension = MACRO_ENABLED_EXTENSIONS.has(ext);
    const archiveExtension = ARCHIVE_EXTENSIONS.has(ext);

    if (dangerousExtension) {
      evidence.push({
        layer: "attachment_qr",
        code: "DANGEROUS_EXECUTABLE_ATTACHMENT",
        description: `Attachment "${att.name}" has a directly executable extension (.${ext}).`,
        scoreContribution: 6,
        source: "local",
      });
    } else if (DANGEROUS_MEDIA_TYPES.has(mediaType)) {
      evidence.push({
        layer: "attachment_qr",
        code: "DANGEROUS_ATTACHMENT_MEDIA_TYPE",
        description: `Attachment "${att.name}" is declared as executable or active content (${mediaType}) despite lacking a recognized executable extension.`,
        scoreContribution: 6,
        source: "local",
      });
    }

    if (macroExtension) {
      evidence.push({
        layer: "attachment_qr",
        code: "MACRO_ENABLED_DOCUMENT",
        description: `Attachment "${att.name}" is a macro-enabled Office document (.${ext}).`,
        scoreContribution: 4,
        source: "local",
      });
    } else if (MACRO_ENABLED_MEDIA_TYPES.has(mediaType)) {
      evidence.push({
        layer: "attachment_qr",
        code: "MACRO_ENABLED_MEDIA_TYPE",
        description: `Attachment "${att.name}" is declared as a macro-enabled Office document (${mediaType}) despite lacking a recognized macro-enabled extension.`,
        scoreContribution: 4,
        source: "local",
      });
    }

    if (archiveExtension) {
      evidence.push({
        layer: "attachment_qr",
        code: "ARCHIVE_ATTACHMENT",
        description: `Attachment "${att.name}" is an archive (.${ext}); contents were not extracted for scanning (spec: bounded local rules only).`,
        scoreContribution: 1,
        source: "local",
      });
    } else if (ARCHIVE_MEDIA_TYPES.has(mediaType)) {
      evidence.push({
        layer: "attachment_qr",
        code: "ARCHIVE_MEDIA_TYPE",
        description: `Attachment "${att.name}" is declared as an archive (${mediaType}); contents were not extracted for scanning.`,
        scoreContribution: 1,
        source: "local",
      });
    }

    if (BIDI_FILENAME_CONTROL.test(att.name)) {
      evidence.push({
        layer: "attachment_qr",
        code: "BIDI_FILENAME_DISGUISE",
        description: `Attachment "${att.name}" contains bidirectional filename controls that can obscure the displayed extension.`,
        scoreContribution: 4,
        source: "local",
      });
    }

    if (att.suspiciousNamePattern || hasDoubleExtension(att.name)) {
      evidence.push({
        layer: "attachment_qr",
        code: "DOUBLE_EXTENSION_DISGUISE",
        description: `Attachment "${att.name}" uses a disguised double-extension pattern.`,
        scoreContribution: 5,
        source: "local",
      });
    }
  }

  const qrLinks = envelope.links.filter((link) => link.source === "qr");
  if (qrLinks.length > 0) {
    evidence.push({
      layer: "attachment_qr",
      code: "QR_CODE_URL_PAYLOAD",
      description: qrLinks.length === 1
        ? "A locally decoded QR image contains a web destination with no visible link text for the user to inspect."
        : `${qrLinks.length} locally decoded QR images contain web destinations with no visible link text for the user to inspect.`,
      scoreContribution: 3,
      source: "local",
    });
  }

  const qrInspection = envelope.diagnostics.qrInspection;
  return {
    layer: "attachment_qr",
    applicable: true,
    evidence,
    incomplete: qrInspection?.incomplete === true,
    incompleteReason: qrInspection?.incompleteReasons.join(" ") || undefined,
    blocksSafeVerdict: qrInspection?.incomplete === true,
  };
}
