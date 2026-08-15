import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import type { LayerResult } from "../verdict.js";

const DANGEROUS_EXTENSIONS = new Set([
  "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse",
  "wsf", "wsh", "msi", "msp", "hta", "jar", "ps1", "psm1", "reg", "cpl",
  "dll", "iso", "img", "vhd", "lnk", "apk",
]);

const MACRO_ENABLED_EXTENSIONS = new Set(["docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam"]);
const ARCHIVE_EXTENSIONS = new Set(["zip", "rar", "7z", "iso", "img", "cab"]);

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

const BIDI_FILENAME_CONTROL = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u;
const BIDI_FILENAME_CONTROLS = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu;
const EVIDENCE_FILENAME_MAX_CHARS = 256;

function normalizedFilename(name: string): string {
  return name
    .normalize("NFKC")
    .replace(BIDI_FILENAME_CONTROLS, "")
    .trim();
}

function evidenceFilename(name: string): string {
  const safe = normalizedFilename(name)
    .replace(/[\u0000-\u001f\u007f]/gu, " ")
    .replace(/\s+/g, " ")
    .trim();
  return (safe || "unnamed").slice(0, EVIDENCE_FILENAME_MAX_CHARS);
}

function extOf(name: string): string {
  const parts = normalizedFilename(name).split(".");
  return parts.length > 1 ? parts[parts.length - 1]!.trim().toLowerCase() : "";
}

function mediaTypeOf(raw: string): string {
  return raw.split(";", 1)[0]!.trim().toLowerCase();
}

function hasDoubleExtension(name: string): boolean {
  const parts = normalizedFilename(name).split(".");
  if (parts.length < 3) return false;
  const knownDocLike = new Set(["pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"]);
  return knownDocLike.has(parts[parts.length - 2]!.trim().toLowerCase());
}

export function attachmentQrLayer(envelope: CanonicalEnvelope): LayerResult {
  const evidence: LayerResult["evidence"] = [];
  const incompleteReasons: string[] = [];

  for (const att of envelope.attachments) {
    const ext = extOf(att.name) || att.extension?.trim().toLowerCase() || "";
    const mediaType = mediaTypeOf(att.mimeType);
    const displayName = evidenceFilename(att.name);
    const dangerousExtension = DANGEROUS_EXTENSIONS.has(ext);
    const macroExtension = MACRO_ENABLED_EXTENSIONS.has(ext);
    const archiveExtension = ARCHIVE_EXTENSIONS.has(ext);
    const security = att.securityInspection;

    if (security?.staticMalware.risk === "high") {
      evidence.push({
        layer: "attachment_qr",
        code: "STATIC_MALWARE_BEHAVIOR",
        description: `Attachment "${displayName}" contains a deterministic local malware-behavior chain or antivirus test signature. Attachment bytes were inspected locally and were not uploaded.`,
        scoreContribution: 7,
        source: "local",
      });
    }

    if (security?.extensionMismatch) {
      evidence.push({
        layer: "attachment_qr",
        code: "ATTACHMENT_MAGIC_EXTENSION_MISMATCH",
        description: `Attachment "${displayName}" has local file-signature bytes that do not match its displayed filename extension.`,
        scoreContribution: 6,
        source: "local",
      });
    }

    if (security?.executableOrScript && !dangerousExtension) {
      evidence.push({
        layer: "attachment_qr",
        code: "OBSERVED_EXECUTABLE_ATTACHMENT",
        description: `Attachment "${displayName}" is executable/script-capable based on locally observed file bytes or active-content structure.`,
        scoreContribution: 7,
        source: "local",
      });
    } else if (dangerousExtension) {
      evidence.push({
        layer: "attachment_qr",
        code: "DANGEROUS_EXECUTABLE_ATTACHMENT",
        description: `Attachment "${displayName}" has a directly executable extension (.${ext}).`,
        scoreContribution: 6,
        source: "local",
      });
    } else if (DANGEROUS_MEDIA_TYPES.has(mediaType)) {
      evidence.push({
        layer: "attachment_qr",
        code: "DANGEROUS_ATTACHMENT_MEDIA_TYPE",
        description: `Attachment "${displayName}" is declared as executable or active content (${mediaType}) despite lacking a recognized executable extension.`,
        scoreContribution: 6,
        source: "local",
      });
    }

    if (security?.macroCapable && !macroExtension) {
      evidence.push({
        layer: "attachment_qr",
        code: "OBSERVED_MACRO_CAPABLE_ATTACHMENT",
        description: `Attachment "${displayName}" contains a locally observed macro-capable document/container indicator.`,
        scoreContribution: 5,
        source: "local",
      });
    } else if (macroExtension) {
      evidence.push({
        layer: "attachment_qr",
        code: "MACRO_ENABLED_DOCUMENT",
        description: `Attachment "${displayName}" is a macro-enabled Office document (.${ext}).`,
        scoreContribution: 4,
        source: "local",
      });
    } else if (MACRO_ENABLED_MEDIA_TYPES.has(mediaType)) {
      evidence.push({
        layer: "attachment_qr",
        code: "MACRO_ENABLED_MEDIA_TYPE",
        description: `Attachment "${displayName}" is declared as a macro-enabled Office document (${mediaType}) despite lacking a recognized macro-enabled extension.`,
        scoreContribution: 4,
        source: "local",
      });
    }

    const archive = security?.archive;
    if ((archive?.executableOrScriptEntries ?? 0) > 0) {
      evidence.push({
        layer: "attachment_qr",
        code: "ARCHIVE_CONTAINS_EXECUTABLE",
        description: `Attachment "${displayName}" has ${archive!.executableOrScriptEntries} executable/script-capable archive entr${archive!.executableOrScriptEntries === 1 ? "y" : "ies"} in its bounded local container directory.`,
        scoreContribution: 7,
        source: "local",
      });
    }
    if ((archive?.encryptedEntries ?? 0) > 0) {
      evidence.push({
        layer: "attachment_qr",
        code: "ENCRYPTED_ARCHIVE_CONTENT",
        description: `Attachment "${displayName}" contains encrypted/password-protected archive entries that could not be inspected without a secret.`,
        scoreContribution: 2,
        source: "local",
      });
    }
    if (archive?.overResourceLimit) {
      evidence.push({
        layer: "attachment_qr",
        code: "ARCHIVE_RESOURCE_LIMIT_EXCEEDED",
        description: `Attachment "${displayName}" declares archive size/compression characteristics above Email Shield's anti-decompression-bomb safety limits.`,
        scoreContribution: 4,
        source: "local",
      });
    }
    if ((archive?.nestedArchiveEntries ?? 0) > 0) {
      evidence.push({
        layer: "attachment_qr",
        code: "NESTED_ARCHIVE_CONTENT",
        description: `Attachment "${displayName}" contains nested archive entries; nested payload bytes were not recursively expanded.`,
        scoreContribution: 2,
        source: "local",
      });
    }

    if (archiveExtension) {
      evidence.push({
        layer: "attachment_qr",
        code: "ARCHIVE_ATTACHMENT",
        description: `Attachment "${displayName}" is an archive (.${ext}); Email Shield inspects bounded container metadata without unbounded extraction.`,
        scoreContribution: 1,
        source: "local",
      });
    } else if (ARCHIVE_MEDIA_TYPES.has(mediaType)) {
      evidence.push({
        layer: "attachment_qr",
        code: "ARCHIVE_MEDIA_TYPE",
        description: `Attachment "${displayName}" is declared as an archive (${mediaType}); bounded local container rules apply.`,
        scoreContribution: 1,
        source: "local",
      });
    }

    if (BIDI_FILENAME_CONTROL.test(att.name)) {
      evidence.push({
        layer: "attachment_qr",
        code: "BIDI_FILENAME_DISGUISE",
        description: `Attachment "${displayName}" contains bidirectional filename controls that can obscure the displayed extension.`,
        scoreContribution: 4,
        source: "local",
      });
    }

    if (att.suspiciousNamePattern || hasDoubleExtension(att.name)) {
      evidence.push({
        layer: "attachment_qr",
        code: "DOUBLE_EXTENSION_DISGUISE",
        description: `Attachment "${displayName}" uses a disguised double-extension pattern.`,
        scoreContribution: 5,
        source: "local",
      });
    }

    if (security?.incomplete) incompleteReasons.push(...security.reasons);
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
  if (qrInspection?.incomplete) incompleteReasons.push(...qrInspection.incompleteReasons);
  const incomplete = incompleteReasons.length > 0;
  return {
    layer: "attachment_qr",
    applicable: true,
    evidence,
    incomplete,
    incompleteReason: [...new Set(incompleteReasons)].join(" ") || undefined,
    blocksSafeVerdict: incomplete,
  };
}
