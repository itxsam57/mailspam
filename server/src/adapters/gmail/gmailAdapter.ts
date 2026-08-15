import { gmail, type gmail_v1 } from "@googleapis/gmail";
import { OAuth2Client } from "google-auth-library";
import { createHash } from "node:crypto";
import type {
  EmailAdapter,
  FetchPage,
  FolderDescriptor,
  RestoreToInboxResult,
  SpamReportResult,
} from "../../canonical/adapter.js";
import type { CanonicalEnvelope, NormalizedFolder } from "../../canonical/envelope.js";
import { normalizeRawMessage } from "../../util/mimeNormalize.js";

export interface GmailOAuthCredentials {
  clientId: string;
  /** Matching Google OAuth client credential used by the guided OIDC flow. */
  clientSecret?: string;
  refreshToken: string;
  /** Stable Google Account subject (`sub`) for guided OAuth sessions. */
  accountSubject?: string;
}

function normalizeLabelToFolder(labelId: string): NormalizedFolder {
  const map: Record<string, NormalizedFolder> = {
    INBOX: "inbox",
    SPAM: "spam",
    SENT: "sent",
    DRAFT: "drafts",
    TRASH: "trash",
    ALL_MAIL: "archive",
  };
  return map[labelId] ?? "other";
}

function inaccessibleGmailEnvelope(input: {
  accountProof: string;
  folder: FolderDescriptor;
  providerNativeId: string;
}): CanonicalEnvelope {
  const stableMessageId = createHash("sha256")
    .update(input.accountProof, "utf8")
    .update("\0", "utf8")
    .update(input.providerNativeId, "utf8")
    .digest("hex");
  return {
    provider: "gmail",
    accountProof: input.accountProof,
    messageId: `gmail-inaccessible-${stableMessageId}`,
    providerNativeId: input.providerNativeId,
    folder: input.folder.normalized,
    providerFolderName: input.folder.providerFolderName,
    from: { displayName: null, address: null, domain: null },
    replyTo: null,
    subject: "",
    date: new Date().toISOString(),
    authentication: { spf: "unknown", dkim: "unknown", dmarc: "unknown", arc: "unknown" },
    textPreview: null,
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "inaccessible",
    parseNotes: ["Gmail message content could not be inspected safely."],
    diagnostics: {
      fetchedAt: new Date().toISOString(),
      sizeBytes: 0,
      encoding: "unknown",
      contentCoverage: "insufficient",
      qrInspection: { supportedImages: 0, decodedUrlCount: 0, incomplete: false, incompleteReasons: [] },
      attachmentHashInspection: { attachments: 0, hashed: 0, incomplete: false, incompleteReasons: [] },
    },
  };
}

/**
 * Isolate individual Gmail message failures without hiding a provider-wide read
 * failure. A message whose raw body was unavailable or whose local MIME/security
 * normalization failed becomes an inaccessible canonical envelope, which the
 * verdict model keeps Unknown. If Gmail cannot read even one listed message in
 * the page, the page still fails so auth/provider outages are never reported as
 * a successful scan.
 */
export async function resolveGmailPageMessages(options: {
  ids: readonly string[];
  signal: AbortSignal;
  readRawMessage: (id: string) => Promise<Buffer | null>;
  normalizeMessage: (raw: Buffer, id: string) => Promise<CanonicalEnvelope>;
  inaccessibleMessage: (id: string) => CanonicalEnvelope;
  concurrency?: number;
}): Promise<CanonicalEnvelope[]> {
  if (options.ids.length === 0) return [];
  const concurrency = Math.max(1, Math.min(options.concurrency ?? 4, options.ids.length));
  const envelopes = new Array<CanonicalEnvelope>(options.ids.length);
  let nextIndex = 0;
  let providerReadSuccesses = 0;

  const workers = Array.from({ length: concurrency }, async () => {
    while (true) {
      if (options.signal.aborted) throw new DOMException("Aborted", "AbortError");
      const index = nextIndex++;
      if (index >= options.ids.length) return;
      const id = options.ids[index]!;
      try {
        const raw = await options.readRawMessage(id);
        providerReadSuccesses += 1;
        if (options.signal.aborted) throw new DOMException("Aborted", "AbortError");
        if (!raw || raw.length === 0) {
          envelopes[index] = options.inaccessibleMessage(id);
          continue;
        }
        try {
          envelopes[index] = await options.normalizeMessage(raw, id);
        } catch {
          if (options.signal.aborted) throw new DOMException("Aborted", "AbortError");
          envelopes[index] = options.inaccessibleMessage(id);
        }
      } catch (error) {
        if (options.signal.aborted || (error instanceof DOMException && error.name === "AbortError")) {
          throw new DOMException("Aborted", "AbortError");
        }
        envelopes[index] = options.inaccessibleMessage(id);
      }
    }
  });

  await Promise.all(workers);
  if (providerReadSuccesses === 0) {
    throw new Error("Gmail could not read any messages in the selected page.");
  }
  return envelopes;
}

/**
 * Gmail adapter (spec Section 3): OAuth-based, uses Gmail API bounded concurrent
 * requests rather than fully serial per-message HTTP calls. Guided desktop OAuth
 * uses Authorization Code + PKCE and carries the matching Google client
 * credentials into token refreshes while keeping them outside browser state.
 *
 * Email Shield currently requests gmail.modify for the guided desktop flow
 * because the existing product includes both mailbox reading and explicit
 * Trash/Spam actions. Google does not support incremental authorization for
 * installed apps, so a fake read-only-to-modify incremental upgrade is not used.
 */
export class GmailAdapter implements EmailAdapter {
  readonly provider = "gmail" as const;
  private gmail: gmail_v1.Gmail | null = null;
  private accountProof: string | null = null;
  private credentials: GmailOAuthCredentials;

  constructor(credentials: GmailOAuthCredentials) {
    this.credentials = credentials;
  }

  async connect(signal: AbortSignal): Promise<void> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const auth = new OAuth2Client(
      this.credentials.clientId,
      this.credentials.clientSecret || undefined,
    );
    auth.setCredentials({ refresh_token: this.credentials.refreshToken });
    this.gmail = gmail({ version: "v1", auth });

    const profile = await this.gmail.users.getProfile({ userId: "me" });
    this.accountProof = createHash("sha256").update(profile.data.emailAddress ?? "unknown").digest("hex");
  }

  async listFolders(signal: AbortSignal): Promise<FolderDescriptor[]> {
    if (!this.gmail) throw new Error("Not connected");
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const res = await this.gmail.users.labels.list({ userId: "me" });
    const systemLabels = ["INBOX", "SPAM", "SENT", "DRAFT", "TRASH"];
    return (res.data.labels ?? [])
      .filter((l) => l.id && systemLabels.includes(l.id))
      .map((l) => {
        const normalized = normalizeLabelToFolder(l.id!);
        return { providerFolderName: l.id!, normalized, includedByDefault: !["sent", "drafts", "trash"].includes(normalized) };
      });
  }

  async fetchPage(
    folder: FolderDescriptor,
    cursor: string | null,
    pageSize: number,
    signal: AbortSignal
  ): Promise<FetchPage> {
    if (!this.gmail || !this.accountProof) throw new Error("Not connected");
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");

    const listRes = await this.gmail.users.messages.list({
      userId: "me",
      labelIds: [folder.providerFolderName],
      maxResults: pageSize,
      pageToken: cursor ?? undefined,
    });
    const ids = (listRes.data.messages ?? []).map((m) => m.id!).filter(Boolean);

    if (ids.length === 0) {
      return { envelopes: [], nextCursor: null, done: true };
    }

    const envelopes = await resolveGmailPageMessages({
      ids,
      signal,
      concurrency: 4,
      readRawMessage: async (id) => {
        const msgRes = await this.gmail!.users.messages.get({ userId: "me", id, format: "raw" });
        const encoded = msgRes.data.raw;
        return typeof encoded === "string" && encoded.length > 0
          ? Buffer.from(encoded, "base64url")
          : null;
      },
      normalizeMessage: async (raw, id) => normalizeRawMessage(raw, {
        provider: "gmail",
        accountProof: this.accountProof!,
        providerFolderName: folder.providerFolderName,
        normalizedFolder: folder.normalized,
        providerNativeId: id,
      }),
      inaccessibleMessage: (id) => inaccessibleGmailEnvelope({
        accountProof: this.accountProof!,
        folder,
        providerNativeId: id,
      }),
    });

    return {
      envelopes,
      nextCursor: listRes.data.nextPageToken ?? null,
      done: !listRes.data.nextPageToken,
    };
  }

  async moveToTrash(messageIds: string[], signal: AbortSignal): Promise<void> {
    if (!this.gmail) throw new Error("Not connected");
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    await this.gmail.users.messages.batchModify({
      userId: "me",
      requestBody: { ids: messageIds, addLabelIds: ["TRASH"], removeLabelIds: ["INBOX"] },
    });
  }

  async reportSpam(messageIds: string[], signal: AbortSignal): Promise<SpamReportResult> {
    if (!this.gmail) throw new Error("Not connected");
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    await this.gmail.users.messages.batchModify({
      userId: "me",
      requestBody: {
        ids: messageIds,
        addLabelIds: ["SPAM"],
        removeLabelIds: ["INBOX", "TRASH"],
      },
    });
    return {
      requested: messageIds.length,
      reported: messageIds.length,
      mode: "provider_spam_label",
    };
  }

  async restoreToInbox(messageIds: string[], signal: AbortSignal): Promise<RestoreToInboxResult> {
    if (!this.gmail) throw new Error("Not connected");
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    if (messageIds.length === 0) return { requested: 0, restored: 0, supported: true, mode: "provider_label_restore" };
    await this.gmail.users.messages.batchModify({
      userId: "me",
      requestBody: {
        ids: messageIds,
        addLabelIds: ["INBOX"],
        removeLabelIds: ["TRASH", "SPAM"],
      },
    });
    return { requested: messageIds.length, restored: messageIds.length, supported: true, mode: "provider_label_restore" };
  }

  async disconnect(): Promise<void> {
    this.gmail = null;
  }
}
