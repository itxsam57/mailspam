import { google, type gmail_v1 } from "googleapis";
import { createHash } from "node:crypto";
import type {
  EmailAdapter,
  FetchPage,
  FolderDescriptor,
  SpamReportResult,
} from "../../canonical/adapter.js";
import type { CanonicalEnvelope, NormalizedFolder } from "../../canonical/envelope.js";
import { normalizeRawMessage } from "../../util/mimeNormalize.js";

export interface GmailOAuthCredentials {
  clientId: string;
  /**
   * Desktop OAuth clients are public clients and cannot keep a client secret.
   * The field remains optional only for the legacy developer credential flow.
   */
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

/**
 * Gmail adapter (spec Section 3): OAuth-based, uses Gmail API bounded concurrent
 * requests rather than fully serial per-message HTTP calls. Guided desktop OAuth
 * uses a public client with PKCE; no client secret is required at runtime.
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
    const auth = new google.auth.OAuth2(
      this.credentials.clientId,
      this.credentials.clientSecret || undefined,
    );
    auth.setCredentials({ refresh_token: this.credentials.refreshToken });
    this.gmail = google.gmail({ version: "v1", auth });

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

    const envelopes: CanonicalEnvelope[] = [];
    const concurrency = 4;
    let nextIndex = 0;
    const workers = Array.from({ length: Math.min(concurrency, ids.length) }, async () => {
      while (true) {
        if (signal.aborted) throw new DOMException("Aborted", "AbortError");
        const index = nextIndex++;
        if (index >= ids.length) return;
        const id = ids[index]!;
        const msgRes = await this.gmail!.users.messages.get({ userId: "me", id, format: "raw" });
        if (signal.aborted) throw new DOMException("Aborted", "AbortError");
        const raw = msgRes.data.raw ? Buffer.from(msgRes.data.raw, "base64url") : Buffer.from("");
        const envelope = await normalizeRawMessage(raw, {
          provider: "gmail",
          accountProof: this.accountProof!,
          providerFolderName: folder.providerFolderName,
          normalizedFolder: folder.normalized,
          providerNativeId: id,
        });
        envelopes[index] = envelope;
      }
    });
    await Promise.all(workers);

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

  async disconnect(): Promise<void> {
    this.gmail = null;
  }
}
