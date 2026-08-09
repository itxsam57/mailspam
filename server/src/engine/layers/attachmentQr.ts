import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import type { LayerResult } from "../verdict.js";

const DANGEROUS_EXTENSIONS = new Set([
  "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse",
  "wsf", "wsh", "msi", "msp", "hta", "jar", "ps1", "psm1", "reg", "cpl",
  "dll", "iso", "img", "vhd", "lnk",
]);

const MACRO_ENABLED_EXTENSIONS = new Set(["docm", "xlsm", "pptm", "dotm", "xltm"]);
const ARCHIVE_EXTENSIONS = new Set(["zip", "rar", "7z", "iso", "img", "cab"]);

function extOf(name: string): string {
  const parts = name.split(".");
  return parts.length > 1 ? parts[parts.length - 1]!.toLowerCase() : "";
}

/** invoice.pdf.exe — more than one extension-like segment before the true extension. */
function hasDoubleExtension(name: string): boolean {
  const parts = name.split(".");
  if (parts.length < 3) return false;
  const knownDocLike = new Set(["pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"]);
  return knownDocLike.has(parts[parts.length - 2]!.toLowerCase());
}

export function attachmentQrLayer(envelope: CanonicalEnvelope): LayerResult {
  const evidence: LayerResult["evidence"] = [];

  for (const att of envelope.attachments) {
    const ext = att.extension?.toLowerCase() ?? extOf(att.name);

    if (DANGEROUS_EXTENSIONS.has(ext)) {
      evidence.push({
        layer: "attachment_qr",
        code: "DANGEROUS_EXECUTABLE_ATTACHMENT",
        description: `Attachment "${att.name}" has a directly executable extension (.${ext}).`,
        scoreContribution: 6,
        source: "local",
      });
    }

    if (MACRO_ENABLED_EXTENSIONS.has(ext)) {
      evidence.push({
        layer: "attachment_qr",
        code: "MACRO_ENABLED_DOCUMENT",
        description: `Attachment "${att.name}" is a macro-enabled Office document (.${ext}).`,
        scoreContribution: 4,
        source: "local",
      });
    }

    if (ARCHIVE_EXTENSIONS.has(ext)) {
      evidence.push({
        layer: "attachment_qr",
        code: "ARCHIVE_ATTACHMENT",
        description: `Attachment "${att.name}" is an archive (.${ext}); contents were not extracted for scanning (spec: bounded local rules only).`,
        scoreContribution: 1,
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
