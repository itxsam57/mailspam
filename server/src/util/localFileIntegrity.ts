import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readSync,
  renameSync,
  rmSync,
} from "node:fs";

export interface LocalFileReadOptions {
  description: string;
  maxBytes: number;
  minBytes?: number;
  exactBytes?: number;
  requireOwnerOnly?: boolean;
}

/**
 * Reads one already-existing local regular file from the same descriptor that
 * was validated. The function never allocates more than the validated file
 * size, refuses POSIX symlinks where O_NOFOLLOW is available, and rejects a
 * file that changes size while it is being read.
 */
export function readBoundedRegularFile(path: string, options: LocalFileReadOptions): Buffer {
  const { description } = options;
  const exactBytes = options.exactBytes;
  const minBytes = exactBytes ?? Math.max(0, options.minBytes ?? 0);
  const maxBytes = exactBytes ?? options.maxBytes;
  if (!Number.isSafeInteger(minBytes) || !Number.isSafeInteger(maxBytes) || minBytes < 0 || maxBytes < minBytes) {
    throw new Error(`${description} has an invalid local file-size contract.`);
  }

  const noFollow = process.platform === "win32" ? 0 : (constants.O_NOFOLLOW ?? 0);
  let descriptor: number;
  try {
    descriptor = openSync(path, constants.O_RDONLY | noFollow);
  } catch {
    throw new Error(`${description} could not be opened safely.`);
  }

  let content: Buffer | null = null;
  try {
    const initial = fstatSync(descriptor);
    if (!initial.isFile()) throw new Error(`${description} must be a regular file.`);
    if (!Number.isSafeInteger(initial.size) || initial.size < minBytes || initial.size > maxBytes) {
      throw new Error(
        exactBytes === undefined
          ? `${description} exceeds its local size contract.`
          : `${description} has an invalid size.`,
      );
    }
    if (options.requireOwnerOnly && process.platform !== "win32" && (initial.mode & 0o077) !== 0) {
      throw new Error(`${description} must not be accessible by group or other users.`);
    }

    content = Buffer.allocUnsafe(initial.size);
    let offset = 0;
    while (offset < content.length) {
      const read = readSync(descriptor, content, offset, content.length - offset, offset);
      if (read <= 0) throw new Error(`${description} changed while being read.`);
      offset += read;
    }

    const overflowProbe = Buffer.allocUnsafe(1);
    const extra = readSync(descriptor, overflowProbe, 0, 1, content.length);
    overflowProbe.fill(0);
    const final = fstatSync(descriptor);
    if (extra !== 0 || final.size !== initial.size) {
      content.fill(0);
      content = null;
      throw new Error(`${description} changed while being read.`);
    }

    return content;
  } catch (error) {
    if (content) content.fill(0);
    throw error;
  } finally {
    closeSync(descriptor);
  }
}

export function readBoundedUtf8File(path: string, options: LocalFileReadOptions): string {
  const content = readBoundedRegularFile(path, options);
  try {
    return content.toString("utf8");
  } finally {
    content.fill(0);
  }
}

/** AES-GCM ciphertext is the same byte length as its plaintext; Base64 expands
 * it to 4*ceil(n/3). 512 bytes safely covers the fixed JSON metadata used by
 * Email Shield's local encrypted envelopes while keeping the on-disk ceiling
 * separate from the plaintext ceiling. */
export function encryptedJsonEnvelopeByteCeiling(maxPlaintextBytes: number): number {
  if (!Number.isSafeInteger(maxPlaintextBytes) || maxPlaintextBytes < 0) {
    throw new Error("Encrypted local storage has an invalid plaintext size contract.");
  }
  return 512 + (4 * Math.ceil(maxPlaintextBytes / 3));
}

/** Replaces one same-directory temporary file with its destination using the
 * platform rename primitive. If replacement fails, the previous destination is
 * preserved and only the uncommitted temporary file is removed. */
export function replaceFileFromTemporaryPath(temporaryPath: string, destinationPath: string): void {
  try {
    renameSync(temporaryPath, destinationPath);
  } catch (error) {
    try { rmSync(temporaryPath, { force: true }); } catch {}
    throw error;
  }
}
