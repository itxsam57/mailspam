import type { NormalizedFolder } from "../../canonical/envelope.js";

export interface ImapFolderLike {
  path?: unknown;
  name?: unknown;
  specialUse?: unknown;
}

function candidateText(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/^\\+/, "")
    .replace(/[_.-]+/g, " ")
    .replace(/\s+/g, " ");
  return normalized || null;
}

export function normalizeImapFolder(folder: ImapFolderLike): NormalizedFolder {
  const candidates = [folder.path, folder.name, folder.specialUse]
    .map(candidateText)
    .filter((value): value is string => Boolean(value));

  if (candidates.some((value) => value === "inbox" || value.endsWith("/inbox"))) return "inbox";
  if (candidates.some((value) => /(^|[ /])(junk|spam)( mail)?$/.test(value))) return "spam";
  if (candidates.some((value) => /(^|[ /])sent( items| messages| mail)?$/.test(value))) return "sent";
  if (candidates.some((value) => /(^|[ /])drafts?$/.test(value))) return "drafts";
  if (candidates.some((value) => /(^|[ /])(trash|deleted items|deleted messages|bin)$/.test(value))) return "trash";
  if (candidates.some((value) => /(^|[ /])(archive|all mail)$/.test(value))) return "archive";
  return "other";
}

export function providerFolderPath(folder: ImapFolderLike): string {
  for (const value of [folder.path, folder.name]) {
    if (typeof value === "string" && value.trim()) return value;
  }
  if (typeof folder.specialUse === "string" && folder.specialUse.trim()) {
    return folder.specialUse.replace(/^\\+/, "");
  }
  throw new Error("IMAP provider returned a folder without a usable path.");
}
