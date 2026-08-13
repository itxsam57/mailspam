export const MAX_ARCHIVE_DIRECTORY_BYTES = 4 * 1024 * 1024;
export const MAX_ARCHIVE_ENTRIES = 256;
export const MAX_ARCHIVE_DECLARED_UNCOMPRESSED_BYTES = 128 * 1024 * 1024;
export const MAX_ARCHIVE_COMPRESSION_RATIO = 100;

export type AttachmentMagicType = "pe_executable" | "elf_executable" | "zip" | "pdf" | "png" | "jpeg" | "ole_compound" | "rtf" | "text_or_unknown";

export interface ArchiveSecurityInspection {
  format: "zip";
  entryCount: number;
  encryptedEntries: number;
  executableOrScriptEntries: number;
  macroCapableEntries: number;
  nestedArchiveEntries: number;
  declaredCompressedBytes: number;
  declaredUncompressedBytes: number;
  maximumCompressionRatio: number;
  overResourceLimit: boolean;
  incomplete: boolean;
  reasons: string[];
}

export interface AttachmentSecurityInspection {
  magicType: AttachmentMagicType;
  extensionMismatch: boolean;
  executableOrScript: boolean;
  macroCapable: boolean;
  archive: ArchiveSecurityInspection | null;
  incomplete: boolean;
  reasons: string[];
}

const EXECUTABLE_EXTENSIONS = new Set(["exe", "dll", "scr", "com", "msi", "msp", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "jar", "lnk", "apk"]);
const MACRO_EXTENSIONS = new Set(["docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "ppam"]);
const ARCHIVE_EXTENSIONS = new Set(["zip", "jar", "apk", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm"]);

function extension(name: string): string {
  const parts = name.normalize("NFKC").trim().toLowerCase().split(".");
  return parts.length > 1 ? parts.at(-1) ?? "" : "";
}

function starts(bytes: Uint8Array, sequence: readonly number[]): boolean {
  if (bytes.length < sequence.length) return false;
  return sequence.every((value, index) => bytes[index] === value);
}

export function attachmentMagicType(bytes: Uint8Array): AttachmentMagicType {
  if (starts(bytes, [0x4d, 0x5a])) return "pe_executable";
  if (starts(bytes, [0x7f, 0x45, 0x4c, 0x46])) return "elf_executable";
  if (starts(bytes, [0x50, 0x4b, 0x03, 0x04]) || starts(bytes, [0x50, 0x4b, 0x05, 0x06]) || starts(bytes, [0x50, 0x4b, 0x07, 0x08])) return "zip";
  if (starts(bytes, [0x25, 0x50, 0x44, 0x46])) return "pdf";
  if (starts(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return "png";
  if (starts(bytes, [0xff, 0xd8, 0xff])) return "jpeg";
  if (starts(bytes, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return "ole_compound";
  const head = Buffer.from(bytes.subarray(0, Math.min(bytes.length, 8))).toString("ascii").toLowerCase();
  if (head.startsWith("{\\rtf")) return "rtf";
  return "text_or_unknown";
}

function magicExpectedExtensions(magic: AttachmentMagicType): ReadonlySet<string> | null {
  switch (magic) {
    case "pe_executable": return new Set(["exe", "dll", "scr", "com"]);
    case "elf_executable": return new Set(["elf", "bin", "run", ""]);
    case "zip": return ARCHIVE_EXTENSIONS;
    case "pdf": return new Set(["pdf"]);
    case "png": return new Set(["png"]);
    case "jpeg": return new Set(["jpg", "jpeg"]);
    case "ole_compound": return new Set(["doc", "xls", "ppt", "msg"]);
    case "rtf": return new Set(["rtf"]);
    default: return null;
  }
}

function u16(bytes: Uint8Array, offset: number): number {
  return bytes[offset]! | (bytes[offset + 1]! << 8);
}

function u32(bytes: Uint8Array, offset: number): number {
  return (bytes[offset]! | (bytes[offset + 1]! << 8) | (bytes[offset + 2]! << 16) | (bytes[offset + 3]! << 24)) >>> 0;
}

function safeEntryName(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("utf8").replace(/\\/g, "/").replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 1024);
}

function inspectZip(bytes: Uint8Array): ArchiveSecurityInspection {
  const reasons: string[] = [];
  const minimumEocd = 22;
  const searchStart = Math.max(0, bytes.length - Math.min(bytes.length, 65_557));
  let eocd = -1;
  for (let index = bytes.length - minimumEocd; index >= searchStart; index -= 1) {
    if (bytes[index] === 0x50 && bytes[index + 1] === 0x4b && bytes[index + 2] === 0x05 && bytes[index + 3] === 0x06) {
      eocd = index;
      break;
    }
  }
  if (eocd < 0 || eocd + 22 > bytes.length) {
    return {
      format: "zip",
      entryCount: 0,
      encryptedEntries: 0,
      executableOrScriptEntries: 0,
      macroCapableEntries: 0,
      nestedArchiveEntries: 0,
      declaredCompressedBytes: 0,
      declaredUncompressedBytes: 0,
      maximumCompressionRatio: 0,
      overResourceLimit: false,
      incomplete: true,
      reasons: ["ZIP end-of-central-directory record was unavailable within the bounded tail scan."],
    };
  }
  const declaredEntries = u16(bytes, eocd + 10);
  const directorySize = u32(bytes, eocd + 12);
  const directoryOffset = u32(bytes, eocd + 16);
  const overDirectoryLimit = directorySize > MAX_ARCHIVE_DIRECTORY_BYTES || declaredEntries > MAX_ARCHIVE_ENTRIES;
  if (overDirectoryLimit) reasons.push("Archive central directory exceeds Email Shield's bounded entry/directory inspection limit.");
  const end = Math.min(bytes.length, directoryOffset + Math.min(directorySize, MAX_ARCHIVE_DIRECTORY_BYTES));
  let cursor = directoryOffset;
  let entries = 0;
  let encryptedEntries = 0;
  let executableOrScriptEntries = 0;
  let macroCapableEntries = 0;
  let nestedArchiveEntries = 0;
  let compressedTotal = 0;
  let uncompressedTotal = 0;
  let maximumCompressionRatio = 0;
  while (cursor + 46 <= end && entries < MAX_ARCHIVE_ENTRIES) {
    if (!(bytes[cursor] === 0x50 && bytes[cursor + 1] === 0x4b && bytes[cursor + 2] === 0x01 && bytes[cursor + 3] === 0x02)) {
      reasons.push("Archive central directory contained an unexpected record and inspection stopped conservatively.");
      break;
    }
    const flags = u16(bytes, cursor + 8);
    const compressed = u32(bytes, cursor + 20);
    const uncompressed = u32(bytes, cursor + 24);
    const nameLength = u16(bytes, cursor + 28);
    const extraLength = u16(bytes, cursor + 30);
    const commentLength = u16(bytes, cursor + 32);
    const recordEnd = cursor + 46 + nameLength + extraLength + commentLength;
    if (recordEnd > end) {
      reasons.push("Archive entry metadata was truncated within the bounded inspection window.");
      break;
    }
    const name = safeEntryName(bytes.subarray(cursor + 46, cursor + 46 + nameLength));
    const ext = extension(name);
    if ((flags & 0x1) !== 0) encryptedEntries += 1;
    if (EXECUTABLE_EXTENSIONS.has(ext)) executableOrScriptEntries += 1;
    if (MACRO_EXTENSIONS.has(ext) || /(?:^|\/)vbaProject\.bin$/i.test(name)) macroCapableEntries += 1;
    if (["zip", "rar", "7z", "iso", "cab", "gz", "bz2", "xz"].includes(ext)) nestedArchiveEntries += 1;
    compressedTotal = Math.min(Number.MAX_SAFE_INTEGER, compressedTotal + compressed);
    uncompressedTotal = Math.min(Number.MAX_SAFE_INTEGER, uncompressedTotal + uncompressed);
    const ratio = compressed === 0 ? (uncompressed > 0 ? Number.POSITIVE_INFINITY : 0) : uncompressed / compressed;
    maximumCompressionRatio = Math.max(maximumCompressionRatio, ratio);
    entries += 1;
    cursor = recordEnd;
  }
  const overResourceLimit = overDirectoryLimit
    || uncompressedTotal > MAX_ARCHIVE_DECLARED_UNCOMPRESSED_BYTES
    || maximumCompressionRatio > MAX_ARCHIVE_COMPRESSION_RATIO;
  if (uncompressedTotal > MAX_ARCHIVE_DECLARED_UNCOMPRESSED_BYTES) reasons.push("Archive declares more uncompressed content than Email Shield's local extraction budget permits.");
  if (maximumCompressionRatio > MAX_ARCHIVE_COMPRESSION_RATIO) reasons.push("Archive declares a compression ratio above Email Shield's anti-decompression-bomb limit.");
  if (encryptedEntries > 0) reasons.push("One or more archive entries are encrypted/password-protected and cannot be inspected locally without the decryption secret.");
  if (nestedArchiveEntries > 0) reasons.push("Nested archive entries were detected; nested payload bytes were not recursively expanded.");
  if (entries < declaredEntries) reasons.push("Not every declared archive entry was inspected within the bounded local limit.");
  return {
    format: "zip",
    entryCount: entries,
    encryptedEntries,
    executableOrScriptEntries,
    macroCapableEntries,
    nestedArchiveEntries,
    declaredCompressedBytes: compressedTotal,
    declaredUncompressedBytes: uncompressedTotal,
    maximumCompressionRatio: Number.isFinite(maximumCompressionRatio) ? Math.round(maximumCompressionRatio * 100) / 100 : Number.MAX_SAFE_INTEGER,
    overResourceLimit,
    incomplete: reasons.length > 0 && (encryptedEntries > 0 || nestedArchiveEntries > 0 || entries < declaredEntries || overResourceLimit),
    reasons: [...new Set(reasons)].slice(0, 12),
  };
}

export function inspectAttachmentSecurity(name: string, mimeType: string, bytes: Uint8Array): AttachmentSecurityInspection {
  const ext = extension(name);
  const magicType = attachmentMagicType(bytes);
  const expected = magicExpectedExtensions(magicType);
  const extensionMismatch = Boolean(expected && !expected.has(ext));
  const executableOrScript = magicType === "pe_executable" || magicType === "elf_executable" || EXECUTABLE_EXTENSIONS.has(ext);
  const macroCapable = MACRO_EXTENSIONS.has(ext) || magicType === "ole_compound" && /macro|vba/i.test(mimeType);
  const archive = magicType === "zip" ? inspectZip(bytes) : null;
  const reasons: string[] = [];
  if (extensionMismatch) reasons.push("Filename extension does not match the locally observed file signature.");
  if (executableOrScript) reasons.push("Attachment is executable/script-capable by extension or observed magic bytes.");
  if (macroCapable || (archive?.macroCapableEntries ?? 0) > 0) reasons.push("Attachment is macro-capable or contains a macro project indicator.");
  if ((archive?.executableOrScriptEntries ?? 0) > 0) reasons.push("Archive contains executable or script-capable filenames.");
  if (archive?.overResourceLimit) reasons.push("Archive exceeds bounded local extraction safety limits and was not expanded.");
  return {
    magicType,
    extensionMismatch,
    executableOrScript,
    macroCapable: macroCapable || (archive?.macroCapableEntries ?? 0) > 0,
    archive,
    incomplete: archive?.incomplete ?? false,
    reasons: [...new Set([...reasons, ...(archive?.reasons ?? [])])].slice(0, 16),
  };
}
