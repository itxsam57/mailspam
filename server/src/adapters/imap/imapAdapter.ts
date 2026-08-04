import { ImapFlow } from "imapflow";
import { createHash } from "node:crypto";
import type { EmailAdapter, FetchPage, FolderDescriptor } from "../../canonical/adapter.js";
import type { CanonicalEnvelope, NormalizedFolder, Provider } from "../../canonical/envelope.js";
import { normalizeRawMessage } from "../../util/mimeNormalize.js";

export interface ImapCredentials {
  host: string;
  port: number;
  secure: boolean;
  user: string;
  appPassword: string;
}

const MAX_MESSAGE_PREFIX_BYTES = 32 * 1024;
const COMMAND_TIMEOUT_MS = 15_000;

function normalizeFolderName(name: string): NormalizedFolder {
  const lower = name.toLowerCase();
  if (lower === "inbox") return "inbox";
  if (/(junk|spam)/.test(lower)) return "spam";
  if (/sent/.test(lower)) return "sent";
  if (/draft/.test(lower)) return "drafts";
  if (/trash|deleted/.test(lower)) return "trash";
  if (/archive|all mail/.test(lower)) return "archive";
  return "other";
}

interface ImapCursor { offset: number; uidValidity: string | null }
function encodeCursor(cursor: ImapCursor): string { return Buffer.from(JSON.stringify(cursor)).toString("base64url"); }
function decodeCursor(cursor: string | null): ImapCursor { if (!cursor) return { offset: 0, uidValidity: null }; try { return JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")); } catch { return { offset: 0, uidValidity: null }; } }
function encodeNativeId(folder: string, uid: number): string { return Buffer.from(JSON.stringify({ folder, uid })).toString("base64url"); }
function decodeNativeId(value: string): { folder: string; uid: number } | null { try { const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")); return typeof parsed.folder === "string" && Number.isInteger(parsed.uid) ? parsed : null; } catch { return null; } }

async function withDeadline<T>(promise: Promise<T>, signal: AbortSignal, ms = COMMAND_TIMEOUT_MS): Promise<T> {
  if (signal.aborted) throw new DOMException("Aborted", "AbortError");
  let timeout: NodeJS.Timeout | undefined;
  return await Promise.race([
    promise,
    new Promise<T>((_, reject) => {
      timeout = setTimeout(() => reject(new Error(`IMAP command exceeded ${ms}ms deadline`)), ms);
      signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
    }),
  ]).finally(() => { if (timeout) clearTimeout(timeout); });
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
      socketTimeout: COMMAND_TIMEOUT_MS,
      greetingTimeout: COMMAND_TIMEOUT_MS,
      connectionTimeout: COMMAND_TIMEOUT_MS,
    } as any);
    this.client = client;
    const onAbort = () => { this.aborted = true; try { client.close(); } catch {} };
    signal.addEventListener("abort", onAbort, { once: true });
    try { await withDeadline(client.connect(), signal); }
    catch (error) { try { client.close(); } catch {} this.client = null; throw error; }
    finally { signal.removeEventListener("abort", onAbort); }
  }

  async listFolders(signal: AbortSignal): Promise<FolderDescriptor[]> {
    const client = this.requireClient();
    const folders = await withDeadline(client.list(), signal);
    return folders.map((folder: any) => {
      const normalized = normalizeFolderName(folder.specialUse ?? folder.name ?? folder.path);
      return { providerFolderName: folder.path, normalized, includedByDefault: !["sent", "drafts", "trash"].includes(normalized) };
    });
  }

  async fetchPage(folder: FolderDescriptor, cursorValue: string | null, pageSize: number, signal: AbortSignal): Promise<FetchPage> {
    const client = this.requireClient();
    const lock = await withDeadline(client.getMailboxLock(folder.providerFolderName), signal);
    try {
      const mailbox: any = client.mailbox;
      const uidValidity = mailbox?.uidValidity ? String(mailbox.uidValidity) : null;
      let cursor = decodeCursor(cursorValue);
      if (cursor.uidValidity && uidValidity && cursor.uidValidity !== uidValidity) cursor = { offset: 0, uidValidity };

      // Search returns the provider's real UIDs. We do not invent continuous UID ranges.
      const allUids = await withDeadline(client.search({ all: true }, { uid: true }) as Promise<number[]>, signal);
      const newestFirst = [...allUids].sort((a, b) => b - a);
      const selected = newestFirst.slice(cursor.offset, cursor.offset + Math.max(1, Math.min(pageSize, 25)));
      if (selected.length === 0) return { envelopes: [], nextCursor: null, done: true };

      const envelopes: CanonicalEnvelope[] = [];
      const uidSet = selected.sort((a, b) => a - b).join(",");
      // Fetch only a bounded RFC822 prefix. It contains headers and normal short-message bodies,
      // but cannot pull multi-megabyte attachments into memory during a normal scan.
      const query: any = { uid: true, source: { start: 0, maxLength: MAX_MESSAGE_PREFIX_BYTES } };
      for await (const message of client.fetch({ uid: uidSet }, query) as any) {
        if (signal.aborted) throw new DOMException("Aborted", "AbortError");
        if (!message.source) continue;
        const envelope = await normalizeRawMessage(message.source, {
          provider: this.provider,
          accountProof: this.accountProof,
          providerFolderName: folder.providerFolderName,
          normalizedFolder: folder.normalized,
          providerNativeId: encodeNativeId(folder.providerFolderName, Number(message.uid)),
        });
        if (Buffer.byteLength(message.source) >= MAX_MESSAGE_PREFIX_BYTES) {
          envelope.parseStatus = "partial";
          envelope.parseNotes.push(`Message content was bounded to ${MAX_MESSAGE_PREFIX_BYTES} bytes; attachments and later MIME parts were not downloaded.`);
        }
        envelopes.push(envelope);
      }

      const nextOffset = cursor.offset + selected.length;
      const done = nextOffset >= newestFirst.length;
      return { envelopes, nextCursor: done ? null : encodeCursor({ offset: nextOffset, uidValidity }), done };
    } finally { lock.release(); }
  }

  async moveToTrash(providerNativeIds: string[], signal: AbortSignal): Promise<void> {
    const client = this.requireClient();
    const byFolder = new Map<string, number[]>();
    for (const value of providerNativeIds) {
      const decoded = decodeNativeId(value);
      if (!decoded) continue;
      const list = byFolder.get(decoded.folder) ?? [];
      list.push(decoded.uid); byFolder.set(decoded.folder, list);
    }
    const trash = (await this.listFolders(signal)).find((folder) => folder.normalized === "trash");
    if (!trash) throw new Error("No Trash folder found on this account.");
    for (const [folder, uids] of byFolder) {
      const lock = await withDeadline(client.getMailboxLock(folder), signal);
      try { await withDeadline(client.messageMove(uids, trash.providerFolderName, { uid: true }) as Promise<any>, signal); }
      finally { lock.release(); }
    }
  }

  async disconnect(): Promise<void> {
    const client = this.client;
    this.client = null;
    if (!client) return;
    if (this.aborted) { try { client.close(); } catch {} return; }
    try { await Promise.race([client.logout(), new Promise((resolve) => setTimeout(resolve, 1000))]); }
    catch { try { client.close(); } catch {} }
  }

  private requireClient(): ImapFlow { if (!this.client) throw new Error("Not connected"); return this.client; }
}

export function createIcloudAdapter(user: string, appPassword: string): ImapAdapter { return new ImapAdapter("icloud", { host: "imap.mail.me.com", port: 993, secure: true, user, appPassword }); }
export function createYahooAdapter(user: string, appPassword: string): ImapAdapter { return new ImapAdapter("yahoo", { host: "imap.mail.yahoo.com", port: 993, secure: true, user, appPassword }); }
export function createGenericImapAdapter(credentials: ImapCredentials): ImapAdapter { return new ImapAdapter("imap", credentials); }
