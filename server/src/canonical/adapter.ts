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

export type SpamReportMode = "provider_spam_label" | "junk_folder_move" | "fixture_junk_move";

export interface SpamReportResult {
  requested: number;
  reported: number;
  mode: SpamReportMode;
}

export interface RestoreToInboxResult {
  requested: number;
  restored: number;
  supported: boolean;
  mode: "provider_label_restore" | "provider_folder_move" | "fixture_restore" | "unsupported";
  reason?: string;
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

  /**
   * Report/move messages into the provider Spam or Junk folder. The adapter
   * must use the provider-native spam label when one exists; generic IMAP
   * moves to the discovered special-use Junk folder. This may be called for an
   * explicit user action or a cryptographically verified signed community
   * warning that crossed the independent-reporter warning threshold. It must
   * never be called automatically from local heuristic scores alone.
   */
  reportSpam(messageIds: string[], signal: AbortSignal): Promise<SpamReportResult>;

  /**
   * Restore a previously protected message to Inbox only when the provider
   * preserves a stable identifier across the move. Adapters that cannot prove
   * a safe inverse MUST return supported:false instead of guessing.
   */
  restoreToInbox(messageIds: string[], signal: AbortSignal): Promise<RestoreToInboxResult>;

  /** Release any open sockets/connections. Safe to call multiple times. */
  disconnect(): Promise<void>;
}

export interface AdapterFactory {
  provider: Provider;
  /** Fixture adapters ignore credentials; live adapters require them. */
  create(credentials: unknown): EmailAdapter;
}
