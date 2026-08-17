import { ImapFlow } from "imapflow";
import { createHash } from "node:crypto";
import type {
  EmailAdapter,
  FetchPage,
  FolderDescriptor,
  SpamReportResult,
} from "../../canonical/adapter.js";
import type { CanonicalEnvelope, NormalizedFolder, Provider } from "../../canonical/envelope.js";
import {
  attachmentHashSizeIsEligible,
  attachmentSha256,
  MAX_ATTACHMENT_HASH_BYTES,
  MAX_ATTACHMENT_HASHES_PER_MESSAGE,
  MAX_ENCODED_ATTACHMENT_HASH_PART_BYTES,
} from "../../util/attachmentHash.js";
import { normalizeRawMessage } from "../../util/mimeNormalize.js";
import {
  analyzeQrImages,
  MAX_QR_IMAGE_BYTES,
  MAX_QR_IMAGES_PER_MESSAGE,
  type QrImageInput,
} from "../../util/qrDecode.js";
import { normalizeImapFolder, providerFolderPath } from "./folderNames.js";
import {
  boundedTextPartWasTruncated,
  buildSyntheticReadableMessage,
  decodeFetchedAttachmentPart,
  decodeFetchedQrImagePart,
  decodeFetchedTextPart,
  inspectBodyStructure,
  type QrImagePart,
  type ReadablePartSelection,
  type ReadableTextPart,
} from "./mimeParts.js";

export interface ImapCredentials {
  host: string;
  port: number;
  secure: boolean;
  user: string;
  appPassword: string;
}

const MAX_ENCODED_TEXT_PART_BYTES = 48 * 1024;
const MAX_DECODED_TEXT_CHARS = 24 * 1024;
export const MAX_COMPLETE_READABLE_PART_BYTES = 256 * 1024;
const MIN_BOUNDED_VISIBLE_CHARS = 500;
const MAX_ENCODED_QR_PART_BYTES = Math.ceil(MAX_QR_IMAGE_BYTES * 1.5) + 4096;
const CONNECT_TIMEOUT_MS = 25_000;
const FOLDER_TIMEOUT_MS = 20_000;
const LOCK_TIMEOUT_MS = 20_000;
const SEARCH_TIMEOUT_MS = 20_000;
const METADATA_TIMEOUT_MS = 30_000;
const TEXT_PART_TIMEOUT_MS = 15_000;
const QR_PART_TIMEOUT_MS = 20_000;
const ATTACHMENT_HASH_PART_TIMEOUT_MS = 20_000;
const MOVE_TIMEOUT_MS = 30_000;
const SOCKET_IDLE_TIMEOUT_MS = 45_000;

export class ImapCommandTimeoutError extends Error {
  readonly code = "IMAP_TIMEOUT";
  constructor(readonly stage: string, readonly timeoutMs: number) {
    super(`IMAP ${stage} exceeded ${timeoutMs}ms deadline`);
    this.name = "ImapCommandTimeoutError";
  }
}

export async function withImapDeadline<T>(
  promise: Promise<T>,
  signal: AbortSignal,
  stage: string,
  timeoutMs: number,
): Promise<T> {
  if (signal.aborted) throw new DOMException("Aborted", "AbortError");

  let timeout: NodeJS.Timeout | undefined;
  let onAbort: (() => void) | undefined;
  const guard = new Promise<T>((_, reject) => {
    onAbort = () => reject(new DOMException("Aborted", "AbortError"));
    signal.addEventListener("abort", onAbort, { once: true });
    timeout = setTimeout(() => reject(new ImapCommandTimeoutError(stage, timeoutMs)), timeoutMs);
  });

  try {
    return await Promise.race([promise, guard]);
  } finally {
    if (timeout) clearTimeout(timeout);
    if (onAbort) signal.removeEventListener("abort", onAbort);
  }
}

interface ImapCursor { offset: number; uidValidity: string | null }
function encodeCursor(cursor: ImapCursor): string { return Buffer.from(JSON.stringify(cursor)).toString("base64url"); }
function decodeCursor(cursor: string | null): ImapCursor { if (!cursor) return { offset: 0, uidValidity: null }; try { return JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")); } catch { return { offset: 0, uidValidity: null }; } }
function encodeNativeId(folder: string, uid: number): string { return Buffer.from(JSON.stringify({ folder, uid })).toString("base64url"); }
function decodeNativeId(value: string): { folder: string; uid: number } | null { try { const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")); return typeof parsed.folder === "string" && Number.isInteger(parsed.uid) ? parsed : null; } catch { return null; } }

interface ImapTextFetchClient {
  fetchOne: (range: string | number, query: Record<string, unknown>, options?: Record<string, unknown>) => Promise<any>;
}

export interface BoundedReadableBodies {
  plain: string | null;
  html: string | null;
  truncated: boolean;
  notes: string[];
}

interface FetchedQrImage extends QrImageInput {
  part: string;
}

interface BoundedQrImages {
  images: FetchedQrImage[];
  supportedCount: number;
  incompleteReasons: string[];
}

export interface BoundedAttachmentHashes {
  hashesByAttachmentIndex: Map<number, string>;
  incompleteReasons: string[];
}

function uniqueReadableParts(selection: ReadablePartSelection): ReadableTextPart[] {
  const byPart = new Map<string, ReadableTextPart>();
  for (const part of [selection.plain, selection.html]) {
    if (part && !byPart.has(part.part.toLowerCase())) byPart.set(part.part.toLowerCase(), part);
  }
  return [...byPart.values()];
}

function bodyPartBuffer(parts: unknown, key: string): Buffer | null {
  if (!(parts instanceof Map)) return null;
  const value = parts.get(key) ?? parts.get(key.toLowerCase()) ?? parts.get(key.toUpperCase());
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  return null;
}

function completeReadablePartIsEligible(part: ReadableTextPart): boolean {
  return part.sizeBytes !== null && part.sizeBytes <= MAX_COMPLETE_READABLE_PART_BYTES;
}

function readablePartFetchLimit(part: ReadableTextPart): number {
  return completeReadablePartIsEligible(part)
    ? part.sizeBytes! + 1
    : MAX_ENCODED_TEXT_PART_BYTES;
}

function readablePartDecodedLimit(part: ReadableTextPart): number {
  return completeReadablePartIsEligible(part)
    ? MAX_COMPLETE_READABLE_PART_BYTES
    : MAX_DECODED_TEXT_CHARS;
}

/**
 * Fetches all selected readable alternatives for one message in one bounded
 * IMAP command. Declared parts that fit the complete-readable budget receive
 * a one-byte sentinel beyond their declared size so completeness can be
 * distinguished from a provider-side prefix. Larger/unknown parts keep the
 * original small bounded prefix path; no whole-message fallback is allowed.
 */
export async function fetchBoundedReadableBodies(
  client: ImapTextFetchClient,
  uid: number,
  selection: ReadablePartSelection,
  signal: AbortSignal,
): Promise<BoundedReadableBodies> {
  const requestedParts = uniqueReadableParts(selection);
  if (!requestedParts.length) {
    return {
      plain: null,
      html: null,
      truncated: false,
      notes: ["No readable text/plain or text/html MIME part was available."],
    };
  }

  const response = await withImapDeadline(
    client.fetchOne(
      uid,
      {
        bodyParts: requestedParts.map((part) => ({
          key: part.part,
          start: 0,
          maxLength: readablePartFetchLimit(part),
        })),
      },
      { uid: true, binary: false },
    ),
    signal,
    `bounded readable MIME fetch for UID ${uid}`,
    TEXT_PART_TIMEOUT_MS,
  );

  const result: BoundedReadableBodies = {
    plain: null,
    html: null,
    truncated: false,
    notes: [],
  };

  if (!response || !(response.bodyParts instanceof Map)) {
    result.notes.push("The provider did not return the requested readable MIME parts.");
    return result;
  }

  for (const part of requestedParts) {
    const rawPart = bodyPartBuffer(response.bodyParts, part.part);
    if (!rawPart) {
      result.notes.push(`The provider did not return the selected ${part.contentType} part.`);
      continue;
    }

    try {
      const rawByteLimit = readablePartFetchLimit(part);
      const decodedCharLimit = readablePartDecodedLimit(part);
      const decoded = await decodeFetchedTextPart(rawPart, part, decodedCharLimit);
      const truncated = boundedTextPartWasTruncated({
        declaredPartBytes: part.sizeBytes,
        fetchedRawBytes: rawPart.length,
        decodedChars: decoded.decodedLength,
        rawByteLimit,
        decodedCharLimit,
      }) || decoded.truncated;
      result.truncated ||= truncated;

      if (part.contentType === "text/plain") result.plain = decoded.text;
      else result.html = decoded.text;
    } catch (error) {
      result.notes.push(`The selected ${part.contentType} part could not be decoded: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  if (!result.plain?.trim() && !result.html?.trim() && !result.notes.length) {
    result.notes.push("The provider returned readable MIME parts, but they contained no decoded text.");
  }

  return result;
}

function qrPartFetchable(part: QrImagePart): boolean {
  return part.sizeBytes === null || part.sizeBytes <= MAX_ENCODED_QR_PART_BYTES;
}

/** Fetch only a bounded number of PNG/JPEG MIME parts for local QR inspection. */
export async function fetchBoundedQrImages(
  client: ImapTextFetchClient,
  uid: number,
  selection: ReadablePartSelection,
  signal: AbortSignal,
): Promise<BoundedQrImages> {
  const supportedCount = selection.qrImages.length;
  const incompleteReasons: string[] = [];
  const selected = selection.qrImages.slice(0, MAX_QR_IMAGES_PER_MESSAGE);
  if (supportedCount > MAX_QR_IMAGES_PER_MESSAGE) {
    incompleteReasons.push(`Only the first ${MAX_QR_IMAGES_PER_MESSAGE} supported images were inspected for QR codes.`);
  }

  const fetchable = selected.filter((part) => {
    if (qrPartFetchable(part)) return true;
    incompleteReasons.push(`A QR-capable image exceeded the bounded IMAP image fetch limit.`);
    return false;
  });
  if (!fetchable.length) return { images: [], supportedCount, incompleteReasons };

  const response = await withImapDeadline(
    client.fetchOne(
      uid,
      {
        bodyParts: fetchable.map((part) => ({
          key: part.part,
          start: 0,
          maxLength: MAX_ENCODED_QR_PART_BYTES,
        })),
      },
      { uid: true, binary: false },
    ),
    signal,
    `bounded QR image fetch for UID ${uid}`,
    QR_PART_TIMEOUT_MS,
  );

  if (!response || !(response.bodyParts instanceof Map)) {
    incompleteReasons.push("The provider did not return the requested QR-capable image parts.");
    return { images: [], supportedCount, incompleteReasons };
  }

  const images: FetchedQrImage[] = [];
  for (const part of fetchable) {
    const rawPart = bodyPartBuffer(response.bodyParts, part.part);
    if (!rawPart) {
      incompleteReasons.push("A requested QR-capable image was not returned by the provider.");
      continue;
    }
    if (rawPart.length >= MAX_ENCODED_QR_PART_BYTES) {
      incompleteReasons.push("A QR-capable image reached the bounded IMAP fetch limit.");
      continue;
    }
    try {
      const content = await decodeFetchedQrImagePart(rawPart, part);
      images.push({ part: part.part, name: part.name, mimeType: part.mimeType, content });
    } catch {
      incompleteReasons.push("A QR-capable image could not be decoded from its MIME transfer encoding.");
    }
  }
  return { images, supportedCount, incompleteReasons };
}

/**
 * Hashes a small bounded set of complete IMAP attachment MIME parts locally.
 * QR image bytes already fetched by the QR layer are reused. No attachment
 * bytes survive this function and no full-message fallback is permitted.
 */
export async function fetchBoundedAttachmentHashes(
  client: ImapTextFetchClient,
  uid: number,
  selection: ReadablePartSelection,
  qrImages: FetchedQrImage[],
  signal: AbortSignal,
): Promise<BoundedAttachmentHashes> {
  const hashesByAttachmentIndex = new Map<number, string>();
  const incompleteReasons: string[] = [];
  const selected = selection.hashableAttachments.slice(0, MAX_ATTACHMENT_HASHES_PER_MESSAGE);

  if (selection.hashableAttachments.length > MAX_ATTACHMENT_HASHES_PER_MESSAGE) {
    incompleteReasons.push(`Only the first ${MAX_ATTACHMENT_HASHES_PER_MESSAGE} attachments were eligible for exact-hash inspection.`);
  }
  if (selection.hashableAttachments.length < selection.attachments.length) {
    incompleteReasons.push("One or more attachment MIME parts could not be addressed safely for exact-hash inspection.");
  }

  const qrByPart = new Map(qrImages.map((image) => [image.part.toLowerCase(), image]));
  const remaining = [] as typeof selected;
  for (const part of selected) {
    const qrImage = qrByPart.get(part.part.toLowerCase());
    if (qrImage && qrImage.content.length <= MAX_ATTACHMENT_HASH_BYTES) {
      hashesByAttachmentIndex.set(part.attachmentIndex, attachmentSha256(qrImage.content));
      continue;
    }
    if (!attachmentHashSizeIsEligible(part.sizeBytes)) {
      incompleteReasons.push("An attachment exceeded the bounded exact-hash size limit.");
      continue;
    }
    remaining.push(part);
  }

  if (!remaining.length) return { hashesByAttachmentIndex, incompleteReasons };

  const response = await withImapDeadline(
    client.fetchOne(
      uid,
      {
        bodyParts: remaining.map((part) => ({
          key: part.part,
          start: 0,
          maxLength: MAX_ENCODED_ATTACHMENT_HASH_PART_BYTES,
        })),
      },
      { uid: true, binary: false },
    ),
    signal,
    `bounded attachment hash fetch for UID ${uid}`,
    ATTACHMENT_HASH_PART_TIMEOUT_MS,
  );

  if (!response || !(response.bodyParts instanceof Map)) {
    incompleteReasons.push("The provider did not return the requested bounded attachment parts for exact hashing.");
    return { hashesByAttachmentIndex, incompleteReasons };
  }

  for (const part of remaining) {
    const rawPart = bodyPartBuffer(response.bodyParts, part.part);
    if (!rawPart) {
      incompleteReasons.push("A requested attachment part was not returned by the provider for exact hashing.");
      continue;
    }
    if (rawPart.length >= MAX_ENCODED_ATTACHMENT_HASH_PART_BYTES) {
      incompleteReasons.push("An attachment reached the bounded encoded fetch limit before exact hashing could complete.");
      continue;
    }
    try {
      const content = await decodeFetchedAttachmentPart(rawPart, part);
      if (content.length > MAX_ATTACHMENT_HASH_BYTES) {
        incompleteReasons.push("A decoded attachment exceeded the bounded exact-hash size limit.");
        continue;
      }
      hashesByAttachmentIndex.set(part.attachmentIndex, attachmentSha256(content));
    } catch {
      incompleteReasons.push("An attachment could not be decoded completely for exact hashing.");
    }
  }

  return { hashesByAttachmentIndex, incompleteReasons };
}

function fallbackHeaders(uid: number): Buffer {
  return Buffer.from([
    "From: unknown <unknown@invalid.local>",
    "Subject: Unreadable message",
    `Message-ID: <imap-${uid}@local.invalid>`,
    `Date: ${new Date().toUTCString()}`,
    "",
  ].join("\r\n"));
}

export class ImapAdapter implements EmailAdapter {
  readonly provider: Provider;
  private client: ImapFlow | null = null;
  private readonly credentials: ImapCredentials;
  private readonly accountProof: string;
  private aborted = false;

  constructor(provider: Provider, credentials: ImapCredentials) {
    this.provider = provider;
    this.credentials = credentials;
    this.accountProof = createHash("sha256").update(credentials.user.trim().toLowerCase()).digest("hex");
  }

  async connect(signal: AbortSignal): Promise<void> {
    if (this.client) throw new Error("Adapter is already connected; create one adapter per operation.");
    this.aborted = false;
    const client = new ImapFlow({
      host: this.credentials.host,
      port: this.credentials.port,
      secure: this.credentials.secure,
      auth: { user: this.credentials.user, pass: this.credentials.appPassword },
      logger: false,
      socketTimeout: SOCKET_IDLE_TIMEOUT_MS,
      greetingTimeout: CONNECT_TIMEOUT_MS,
      connectionTimeout: CONNECT_TIMEOUT_MS,
    } as any);
    this.client = client;
    const onAbort = () => { this.aborted = true; try { client.close(); } catch {} };
    signal.addEventListener("abort", onAbort, { once: true });
    try {
      await withImapDeadline(client.connect(), signal, "connection", CONNECT_TIMEOUT_MS);
    } catch (error) {
      try { client.close(); } catch {}
      this.client = null;
      throw error;
    } finally {
      signal.removeEventListener("abort", onAbort);
    }
  }

  async listFolders(signal: AbortSignal): Promise<FolderDescriptor[]> {
    const client = this.requireClient();
    const folders = await withImapDeadline(client.list(), signal, "folder discovery", FOLDER_TIMEOUT_MS);
    return folders.map((folder: any) => {
      const providerFolderName = providerFolderPath(folder);
      const normalized = normalizeImapFolder(folder);
      return {
        providerFolderName,
        normalized,
        includedByDefault: !["sent", "drafts", "trash"].includes(normalized),
      };
    });
  }

  async mailboxCheckpoint(signal: AbortSignal): Promise<string> {
    const client = this.requireClient();
    const folders = (await this.listFolders(signal))
      .filter((folder) => folder.normalized === "inbox" || folder.normalized === "spam")
      .sort((left, right) => left.normalized.localeCompare(right.normalized) || left.providerFolderName.localeCompare(right.providerFolderName));
    if (!folders.some((folder) => folder.normalized === "inbox")) {
      throw new Error("IMAP mailbox checkpoint could not locate Inbox.");
    }

    const snapshots: string[] = [];
    for (const folder of folders) {
      const lock = await withImapDeadline(
        client.getMailboxLock(folder.providerFolderName),
        signal,
        `mailbox checkpoint lock for ${folder.providerFolderName}`,
        LOCK_TIMEOUT_MS,
      );
      try {
        const mailbox: any = client.mailbox;
        const uidValidity = mailbox?.uidValidity === undefined || mailbox?.uidValidity === null ? "" : String(mailbox.uidValidity);
        const uidNext = mailbox?.uidNext === undefined || mailbox?.uidNext === null ? "" : String(mailbox.uidNext);
        const exists = Number.isSafeInteger(Number(mailbox?.exists)) ? Number(mailbox.exists) : 0;
        snapshots.push(`${folder.normalized}\0${folder.providerFolderName}\0${uidValidity}\0${uidNext}\0${exists}`);
      } finally {
        lock.release();
      }
    }

    return createHash("sha256")
      .update(["email-shield-imap-checkpoint-v1", this.provider, ...snapshots].join("\0"), "utf8")
      .digest("hex");
  }

  async fetchPage(folder: FolderDescriptor, cursorValue: string | null, pageSize: number, signal: AbortSignal): Promise<FetchPage> {
    const client = this.requireClient();
    const lock = await withImapDeadline(
      client.getMailboxLock(folder.providerFolderName),
      signal,
      `mailbox lock for ${folder.providerFolderName}`,
      LOCK_TIMEOUT_MS,
    );
    try {
      const mailbox: any = client.mailbox;
      const uidValidity = mailbox?.uidValidity ? String(mailbox.uidValidity) : null;
      let cursor = decodeCursor(cursorValue);
      if (cursor.uidValidity && uidValidity && cursor.uidValidity !== uidValidity) cursor = { offset: 0, uidValidity };

      const allUids = await withImapDeadline(
        client.search({ all: true }, { uid: true }) as Promise<number[]>,
        signal,
        `UID search in ${folder.providerFolderName}`,
        SEARCH_TIMEOUT_MS,
      );
      const newestFirst = [...allUids].sort((a, b) => b - a);
      const selected = newestFirst.slice(cursor.offset, cursor.offset + Math.max(1, Math.min(pageSize, 25)));
      if (selected.length === 0) return { envelopes: [], nextCursor: null, done: true };

      const metadataMessages = await withImapDeadline(
        client.fetchAll(selected, {
          uid: true,
          headers: true,
          bodyStructure: true,
          size: true,
        }, { uid: true }) as Promise<any[]>,
        signal,
        `metadata fetch for ${selected.length} messages in ${folder.providerFolderName}`,
        METADATA_TIMEOUT_MS,
      );
      const metadataByUid = new Map<number, any>(metadataMessages.map((message) => [Number(message.uid), message]));

      const envelopes: CanonicalEnvelope[] = [];
      for (const uid of selected) {
        if (signal.aborted) throw new DOMException("Aborted", "AbortError");
        const message = metadataByUid.get(uid);
        const headers = message?.headers ?? fallbackHeaders(uid);
        const selection = inspectBodyStructure(message?.bodyStructure);

        let bodies: BoundedReadableBodies = { plain: null, html: null, truncated: false, notes: [] };
        try {
          bodies = await fetchBoundedReadableBodies(client as unknown as ImapTextFetchClient, uid, selection, signal);
        } catch (error) {
          if (signal.aborted || error instanceof ImapCommandTimeoutError) throw error;
          bodies.notes.push(`Readable MIME content could not be downloaded: ${error instanceof Error ? error.message : String(error)}`);
        }

        let qrImages: BoundedQrImages = { images: [], supportedCount: selection.qrImages.length, incompleteReasons: [] };
        try {
          qrImages = await fetchBoundedQrImages(client as unknown as ImapTextFetchClient, uid, selection, signal);
        } catch (error) {
          if (signal.aborted || error instanceof ImapCommandTimeoutError) throw error;
          qrImages.incompleteReasons.push(`QR-capable image content could not be downloaded: ${error instanceof Error ? error.message : String(error)}`);
        }

        let attachmentHashes: BoundedAttachmentHashes = { hashesByAttachmentIndex: new Map(), incompleteReasons: [] };
        try {
          attachmentHashes = await fetchBoundedAttachmentHashes(
            client as unknown as ImapTextFetchClient,
            uid,
            selection,
            qrImages.images,
            signal,
          );
        } catch (error) {
          if (signal.aborted || error instanceof ImapCommandTimeoutError) throw error;
          attachmentHashes.incompleteReasons.push(`Attachment exact-hash inspection could not complete: ${error instanceof Error ? error.message : String(error)}`);
        }

        const syntheticRaw = buildSyntheticReadableMessage({
          headers,
          plainBody: bodies.plain,
          htmlBody: bodies.html,
        });
        const envelope = await normalizeRawMessage(syntheticRaw, {
          provider: this.provider,
          accountProof: this.accountProof,
          providerFolderName: folder.providerFolderName,
          normalizedFolder: folder.normalized,
          providerNativeId: encodeNativeId(folder.providerFolderName, uid),
        });
        envelope.attachments = selection.attachments.map((attachment, index) => ({
          ...attachment,
          sha256: attachmentHashes.hashesByAttachmentIndex.get(index) ?? null,
        }));
        envelope.diagnostics.sizeBytes = Number(message?.size ?? syntheticRaw.length);
        const hashedAttachments = envelope.attachments.filter((attachment) => attachment.sha256 !== null).length;
        const hashIncomplete = hashedAttachments !== envelope.attachments.length;
        envelope.diagnostics.attachmentHashInspection = {
          attachments: envelope.attachments.length,
          hashed: hashedAttachments,
          incomplete: hashIncomplete,
          incompleteReasons: hashIncomplete
            ? [...new Set([
                ...attachmentHashes.incompleteReasons,
                "One or more attachment bodies were not fully available within the bounded exact-hash inspection limits.",
              ])]
            : [],
        };

        const qrAnalysis = analyzeQrImages(qrImages.images);
        envelope.links.push(...qrAnalysis.links);
        const qrIncompleteReasons = [...qrImages.incompleteReasons, ...qrAnalysis.incompleteReasons];
        envelope.diagnostics.qrInspection = {
          supportedImages: qrImages.supportedCount,
          decodedUrlCount: qrAnalysis.links.length,
          incomplete: qrIncompleteReasons.length > 0,
          incompleteReasons: qrIncompleteReasons,
        };
        envelope.parseNotes.push(...qrIncompleteReasons);

        const hasReadableBody = Boolean(bodies.plain?.trim() || bodies.html?.trim());
        const readableText = `${envelope.textPreview ?? ""} ${envelope.htmlSignals?.extractedText ?? ""}`.trim();
        if (!hasReadableBody) {
          envelope.parseStatus = "partial";
          envelope.diagnostics.contentCoverage = "insufficient";
          envelope.parseNotes.push(...(bodies.notes.length
            ? bodies.notes
            : ["No decoded readable message text was returned by the provider."]));
        } else if (bodies.truncated) {
          envelope.parseStatus = "partial";
          envelope.diagnostics.contentCoverage = readableText.length >= MIN_BOUNDED_VISIBLE_CHARS
            ? "bounded_sufficient"
            : "insufficient";
          envelope.parseNotes.push(`Readable MIME content was bounded to ${MAX_DECODED_TEXT_CHARS} decoded characters per alternative.`);
          envelope.parseNotes.push(...bodies.notes);
        } else if (bodies.notes.length) {
          envelope.parseStatus = "partial";
          envelope.diagnostics.contentCoverage = readableText.length >= MIN_BOUNDED_VISIBLE_CHARS
            ? "bounded_sufficient"
            : "insufficient";
          envelope.parseNotes.push(...bodies.notes);
        } else {
          envelope.parseStatus = "complete";
          envelope.diagnostics.contentCoverage = "complete";
          envelope.parseNotes = envelope.parseNotes.filter((note) => note !== "No text or HTML body could be extracted.");
        }
        envelopes.push(envelope);
      }

      const nextOffset = cursor.offset + selected.length;
      const done = nextOffset >= newestFirst.length;
      return { envelopes, nextCursor: done ? null : encodeCursor({ offset: nextOffset, uidValidity }), done };
    } finally {
      lock.release();
    }
  }

  private decodeByFolder(providerNativeIds: string[]): Map<string, number[]> {
    const byFolder = new Map<string, number[]>();
    for (const value of providerNativeIds) {
      const decoded = decodeNativeId(value);
      if (!decoded) throw new Error("An IMAP message identifier was invalid or expired.");
      const list = byFolder.get(decoded.folder) ?? [];
      list.push(decoded.uid);
      byFolder.set(decoded.folder, list);
    }
    return byFolder;
  }

  private async moveToSpecialFolder(
    providerNativeIds: string[],
    targetType: Extract<NormalizedFolder, "trash" | "spam">,
    targetLabel: string,
    signal: AbortSignal,
  ): Promise<void> {
    const client = this.requireClient();
    const byFolder = this.decodeByFolder(providerNativeIds);
    const target = (await this.listFolders(signal)).find((folder) => folder.normalized === targetType);
    if (!target) throw new Error(`No ${targetLabel} folder was found on this account.`);

    for (const [folder, uids] of byFolder) {
      if (folder === target.providerFolderName) continue;
      const lock = await withImapDeadline(
        client.getMailboxLock(folder),
        signal,
        `mailbox lock for ${folder}`,
        LOCK_TIMEOUT_MS,
      );
      try {
        await withImapDeadline(
          client.messageMove(uids, target.providerFolderName, { uid: true }) as Promise<any>,
          signal,
          `move of ${uids.length} message(s) from ${folder} to ${targetLabel}`,
          MOVE_TIMEOUT_MS,
        );
      } finally {
        lock.release();
      }
    }
  }

  async moveToTrash(providerNativeIds: string[], signal: AbortSignal): Promise<void> {
    await this.moveToSpecialFolder(providerNativeIds, "trash", "Trash", signal);
  }

  async reportSpam(providerNativeIds: string[], signal: AbortSignal): Promise<SpamReportResult> {
    await this.moveToSpecialFolder(providerNativeIds, "spam", "Spam/Junk", signal);
    return {
      requested: providerNativeIds.length,
      reported: providerNativeIds.length,
      mode: "junk_folder_move",
    };
  }

  async disconnect(): Promise<void> {
    const client = this.client;
    this.client = null;
    if (!client) return;
    if (this.aborted) {
      try { client.close(); } catch {}
      return;
    }

    let logoutCompleted = false;
    try {
      await Promise.race([
        client.logout().then(() => { logoutCompleted = true; }),
        new Promise<void>((resolve) => setTimeout(resolve, 1000)),
      ]);
    } catch {}

    if (!logoutCompleted) {
      try { client.close(); } catch {}
    }
  }

  private requireClient(): ImapFlow {
    if (!this.client) throw new Error("Not connected");
    return this.client;
  }
}

export function createIcloudAdapter(user: string, appPassword: string): ImapAdapter { return new ImapAdapter("icloud", { host: "imap.mail.me.com", port: 993, secure: true, user, appPassword }); }
export function createYahooAdapter(user: string, appPassword: string): ImapAdapter { return new ImapAdapter("yahoo", { host: "imap.mail.yahoo.com", port: 993, secure: true, user, appPassword }); }
export function createGenericImapAdapter(credentials: ImapCredentials): ImapAdapter { return new ImapAdapter("imap", credentials); }