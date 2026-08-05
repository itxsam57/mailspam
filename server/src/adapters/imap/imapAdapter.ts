import { ImapFlow } from "imapflow";
import { createHash } from "node:crypto";
import type {
  EmailAdapter,
  FetchPage,
  FolderDescriptor,
  SpamReportResult,
} from "../../canonical/adapter.js";
import type { CanonicalEnvelope, NormalizedFolder, Provider } from "../../canonical/envelope.js";
import { normalizeRawMessage } from "../../util/mimeNormalize.js";
import { normalizeImapFolder, providerFolderPath } from "./folderNames.js";
import {
  buildSyntheticRawMessage,
  decodeTextBuffer,
  inspectBodyStructure,
} from "./mimeParts.js";

export interface ImapCredentials {
  host: string;
  port: number;
  secure: boolean;
  user: string;
  appPassword: string;
}

const MAX_TEXT_PART_BYTES = 24 * 1024;
const MIN_USEFUL_PLAIN_TEXT_CHARS = 80;
const MIN_BOUNDED_VISIBLE_CHARS = 500;
const CONNECT_TIMEOUT_MS = 25_000;
const FOLDER_TIMEOUT_MS = 20_000;
const LOCK_TIMEOUT_MS = 20_000;
const SEARCH_TIMEOUT_MS = 20_000;
const METADATA_TIMEOUT_MS = 30_000;
const TEXT_PART_TIMEOUT_MS = 20_000;
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

async function collectStream(stream: AsyncIterable<Buffer | Uint8Array | string>, signal: AbortSignal): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

async function downloadTextPart(
  client: ImapFlow,
  uid: number,
  part: string,
  signal: AbortSignal,
): Promise<{ text: string; contentType: "text/plain" | "text/html"; truncated: boolean }> {
  const stage = `text-part download for UID ${uid}`;
  const download = await withImapDeadline(
    client.download(uid, part, { uid: true, maxBytes: MAX_TEXT_PART_BYTES }) as Promise<any>,
    signal,
    stage,
    TEXT_PART_TIMEOUT_MS,
  );
  const buffer = await withImapDeadline(
    collectStream(download.content, signal),
    signal,
    `${stage} stream`,
    TEXT_PART_TIMEOUT_MS,
  );
  const contentType = String(download.meta?.contentType ?? "text/plain").toLowerCase() === "text/html"
    ? "text/html"
    : "text/plain";
  const expectedSize = Number(download.meta?.expectedSize ?? buffer.length);
  return {
    text: decodeTextBuffer(buffer, download.meta?.charset),
    contentType,
    truncated: Number.isFinite(expectedSize) && expectedSize > buffer.length,
  };
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

        let body = "";
        let contentType: "text/plain" | "text/html" = "text/plain";
        let truncated = false;
        const parseNotes: string[] = [];

        try {
          if (selection.plainPart) {
            const plain = await downloadTextPart(client, uid, selection.plainPart, signal);
            body = plain.text;
            contentType = "text/plain";
            truncated = plain.truncated;

            if (body.trim().length < MIN_USEFUL_PLAIN_TEXT_CHARS && selection.htmlPart) {
              const html = await downloadTextPart(client, uid, selection.htmlPart, signal);
              body = html.text;
              contentType = "text/html";
              truncated = html.truncated;
            }
          } else if (selection.htmlPart) {
            const html = await downloadTextPart(client, uid, selection.htmlPart, signal);
            body = html.text;
            contentType = "text/html";
            truncated = html.truncated;
          } else {
            parseNotes.push("No readable text/plain or text/html MIME part was available.");
          }
        } catch (error) {
          if (signal.aborted || error instanceof ImapCommandTimeoutError) throw error;
          parseNotes.push(`Readable MIME part could not be downloaded: ${(error as Error).message}`);
        }

        const syntheticRaw = buildSyntheticRawMessage({ headers, body, contentType });
        const envelope = await normalizeRawMessage(syntheticRaw, {
          provider: this.provider,
          accountProof: this.accountProof,
          providerFolderName: folder.providerFolderName,
          normalizedFolder: folder.normalized,
          providerNativeId: encodeNativeId(folder.providerFolderName, uid),
        });
        envelope.attachments = selection.attachments;
        envelope.diagnostics.sizeBytes = Number(message?.size ?? syntheticRaw.length);

        const readableText = `${envelope.textPreview ?? ""} ${envelope.htmlSignals?.extractedText ?? ""}`.trim();
        if (!body.trim() || parseNotes.length) {
          envelope.parseStatus = "partial";
          envelope.diagnostics.contentCoverage = "insufficient";
          envelope.parseNotes.push(...parseNotes);
        } else if (truncated) {
          envelope.parseStatus = "partial";
          envelope.diagnostics.contentCoverage = readableText.length >= MIN_BOUNDED_VISIBLE_CHARS
            ? "bounded_sufficient"
            : "insufficient";
          envelope.parseNotes.push(`Readable text was bounded to ${MAX_TEXT_PART_BYTES} bytes.`);
        } else {
          envelope.diagnostics.contentCoverage = "complete";
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
