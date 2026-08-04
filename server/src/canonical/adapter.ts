import type { CanonicalEnvelope, NormalizedFolder, Provider } from "./envelope.js";

/** A page of messages, plus a resumable cursor for Full Mailbox Audit. */
export interface FetchPage {
  envelopes: CanonicalEnvelope[];
  nextCursor: string | null;
  /** True once the folder has been fully walked (cursor is exhausted). */
  done: boolean;
}

export interface FolderDescriptor {
  providerFolderName: string;
  normalized: NormalizedFolder;
  /** Whether this folder is included by default (Sent/Drafts/Trash excluded unless explicitly selected — spec 8.2). */
  includedByDefault: boolean;
}

/**
 * Every cancellation-capable call takes an AbortSignal and MUST respect it:
 * - stop issuing new provider requests once aborted
 * - reject in-flight command promises rather than resolve them
 * - never write to a destroyed transport (spec regression: "Dead socket
 *   cleanup hung on LOGOUT")
 */
export interface EmailAdapter {
  readonly provider: Provider;

  connect(signal: AbortSignal): Promise<void>;

  /** Must not download mailbox contents to enumerate folders (spec 3.1). */
  listFolders(signal: AbortSignal): Promise<FolderDescriptor[]>;

  /**
   * Fetch one bounded page of messages from a folder, batched using
   * provider-native batch calls (spec: "one batch fetch per page, not one
   * network command per message").
   */
  fetchPage(
    folder: FolderDescriptor,
    cursor: string | null,
    pageSize: number,
    signal: AbortSignal
  ): Promise<FetchPage>;

  /** Move messages to Trash via provider API/IMAP. Must be idempotent. */
  moveToTrash(messageIds: string[], signal: AbortSignal): Promise<void>;

  /** Release any open sockets/connections. Safe to call multiple times. */
  disconnect(): Promise<void>;
}

export interface AdapterFactory {
  provider: Provider;
  /** Fixture adapters ignore credentials; live adapters require them. */
  create(credentials: unknown): EmailAdapter;
}
