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
import {
  GmailMessageReadPacer,
  isMissingGmailMessageError,
  runGmailReadWithBackoff,
} from "./gmailReadPolicy.js";

export interface GmailOAuthCredentials {
  clientId: string;
  /** Matching Google OAuth client credential used by the guided OIDC flow. */
  clientSecret?: string;
  refreshToken: string;
  /** Stable Google Account subject (`sub`) for guided OAuth sessions. */
  accountSubject?: string;
}

const GMAIL_ARCHIVE_QUERY = "in:archive";

function normalizeLabelToFolder(labelId: string): NormalizedFolder {
  const map: Record<string, NormalizedFolder> = {
    INBOX: "inbox",
    SPAM: "spam",
    SENT: "sent",
    DRAFT: "drafts",
    TRASH: "trash",
  };
  return map[labelId] ?? "other";
}

/**
 * Build the provider-neutral folder plan from Gmail's real system labels.
 * Gmail's REST API does not expose Archive as a normal label ID, so Archive is
 * represented by a synthetic descriptor whose fetch is implemented with the
 * provider-native `in:archive` search query instead of inventing a label ID.
 */
export function resolveGmailFolderDescriptors(labelIds: readonly string[]): FolderDescriptor[] {
  const systemLabels = new Set(["INBOX", "SPAM", "SENT", "DRAFT", "TRASH"]);
  const folders = labelIds
    .filter((labelId) => systemLabels.has(labelId))
    .map((labelId) => {
      const normalized = normalizeLabelToFolder(labelId);
      return {
        providerFolderName: labelId,
        normalized,
        includedByDefault: !["sent", "drafts", "trash"].includes(normalized),
      } satisfies FolderDescriptor;
    });
  folders.push({
    providerFolderName: GMAIL_ARCHIVE_QUERY,
    normalized: "archive",
    includedByDefault: true,
  });
  return folders;
}

/**
 * Translate a provider-neutral Gmail folder into one bounded messages.list call.
 * Spam/Trash require includeSpamTrash. Archive is not a label; Gmail exposes it
 * through its search grammar, so no fake labelId is sent for that source.
 */
export function gmailMessageListParameters(
  folder: FolderDescriptor,
  cursor: string | null,
  pageSize: number,
): gmail_v1.Params$Resource$Users$Messages$List {
  const base: gmail_v1.Params$Resource$Users$Messages$List = {
    userId: "me",
    maxResults: pageSize,
    pageToken: cursor ?? undefined,
  };
  if (folder.normalized === "archive") {
    return { ...base, q: GMAIL_ARCHIVE_QUERY };
  }
  return {
    ...base,
    labelIds: [folder.providerFolderName],
    ...(["spam", "trash"].includes(folder.normalized) ? { includeSpamTrash: true } : {}),
  };
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
 * verdict model keeps Unknown. Messages that disappeared after messages.list
 * (404/410) are skipped like vanished IMAP UIDs rather than collapsing a Full
 * Audit page. If Gmail cannot successfully answer or definitively invalidate
 * any listed message in the page, the page still fails closed.
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
  const envelopes = new Array<CanonicalEnvelope | null>(options.ids.length).fill(null);
  let nextIndex = 0;
  let providerReadSuccesses = 0;
  let definitivelyMissingMessages = 0;

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
        if (isMissingGmailMessageError(error)) {
          definitivelyMissingMessages += 1;
          envelopes[index] = null;
          continue;
        }
        envelopes[index] = options.inaccessibleMessage(id);
      }
    }
  });

  await Promise.all(workers);
  if (providerReadSuccesses === 0 && definitivelyMissingMessages === 0) {
    throw new Error("Gmail could not read any messages in the selected page.");
  }
  return envelopes.filter((envelope): envelope is CanonicalEnvelope => envelope !== null);
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
  private readonly messageReadPacer = new GmailMessageReadPacer();

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

    const profile = await runGmailReadWithBackoff(
      () => this.gmail!.users.getProfile({ userId: "me" }),
      signal,
    );
    this.accountProof = createHash("sha256").update(profile.data.emailAddress ?? "unknown").digest("hex");
  }

  async listFolders(signal: AbortSignal): Promise<FolderDescriptor[]> {
    if (!this.gmail) throw new Error("Not connected");
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const res = await runGmailReadWithBackoff(
      () => this.gmail!.users.labels.list({ userId: "me" }),
      signal,
    );
    return resolveGmailFolderDescriptors(
      (res.data.labels ?? []).map((label) => label.id).filter((id): id is string => Boolean(id)),
    );
  }

  async mailboxCheckpoint(signal: AbortSignal): Promise<string> {
    if (!this.gmail) throw new Error("Not connected");
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const profile = await runGmailReadWithBackoff(
      () => this.gmail!.users.getProfile({ userId: "me" }),
      signal,
    );
    const historyId = profile.data.historyId;
    if (typeof historyId !== "string" || !/^\d+$/.test(historyId)) {
      throw new Error("Gmail profile did not provide a valid history checkpoint.");
    }
    return createHash("sha256")
      .update(`email-shield-gmail-checkpoint-v1\0${historyId}`, "utf8")
      .digest("hex");
  }

  async fetchPage(
    folder: FolderDescriptor,
    cursor: string | null,
    pageSize: number,
    signal: AbortSignal
  ): Promise<FetchPage> {
    if (!this.gmail || !this.accountProof) throw new Error("Not connected");
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");

    const listRes = await runGmailReadWithBackoff(
      () => this.gmail!.users.messages.list(
        gmailMessageListParameters(folder, cursor, pageSize),
      ),
      signal,
    );
    const ids = (listRes.data.messages ?? []).map((m) => m.id!).filter(Boolean);

    if (ids.length === 0) {
      return {
        envelopes: [],
        nextCursor: listRes.data.nextPageToken ?? null,
        done: !listRes.data.nextPageToken,
      };
    }

    const envelopes = await resolveGmailPageMessages({
      ids,
      signal,
      concurrency: 4,
      readRawMessage: async (id) => {
        const msgRes = await runGmailReadWithBackoff(
          () => this.gmail!.users.messages.get({ userId: "me", id, format: "raw" }),
          signal,
          { beforeAttempt: async () => this.messageReadPacer.wait(signal) },
        );
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