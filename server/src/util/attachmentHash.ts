import { createHash } from "node:crypto";

/**
 * Exact attachment-hash intelligence is useful only when Email Shield has the
 * complete decoded attachment bytes. Keep live IMAP acquisition deliberately
 * bounded so this feature cannot turn mailbox scans into bulk attachment
 * downloads.
 */
export const MAX_ATTACHMENT_HASHES_PER_MESSAGE = 4;
export const MAX_ATTACHMENT_HASH_BYTES = 2 * 1024 * 1024;
export const MAX_ENCODED_ATTACHMENT_HASH_PART_BYTES = Math.ceil(MAX_ATTACHMENT_HASH_BYTES * 1.5) + 4096;

export function attachmentSha256(content: Buffer | Uint8Array): string {
  return createHash("sha256").update(content).digest("hex");
}

export function attachmentHashSizeIsEligible(sizeBytes: number | null): boolean {
  return sizeBytes === null || sizeBytes <= MAX_ATTACHMENT_HASH_BYTES;
}
