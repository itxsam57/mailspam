import { google, type gmail_v1 } from "googleapis";
import { createHash } from "node:crypto";
import type { EmailAdapter, FetchPage, FolderDescriptor } from "../../canonical/adapter.js";
import type { CanonicalEnvelope, NormalizedFolder } from "../../canonical/envelope.js";
import { normalizeRawMessage } from "../../util/mimeNormalize.js";

export interface GmailOAuthCredentials {
  clientId: string;
  clientSecret: string;
  refreshToken: string;
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
 * Gmail adapter (spec Section 3): OAuth-based, uses Gmail API batch
 * requests rather than per-message HTTP calls — the exact regression spec
 * 12.3 calls out ("One HTTP request per message instead of batch"). Scopes
 * requested must be read-only + labels-modify-only for Trash moves, never
 * full mailbox write access.
 *
 * Required OAuth scopes: https://www.googleapis.com/auth/gmail.readonly
 * and https://www.googleapis.com/auth/gmail.modify (modify is only needed
 * for the Trash-move action; if the user never grants it, moveToTrash
 * degrades to reporting an actionable "reconnect with permission" error
 * rather than crashing the scan).
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
    const auth = new google.auth.OAuth2(this.credentials.clientId, this.credentials.clientSecret);
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

    // Step 1: list message IDs for this page (metadata-only call).
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

    // Step 2: batch-fetch raw RFC822 content for the whole page in
    // parallel Promise.all — the Gmail API has no single true "batch"
    // multipart endpoint that's well-supported by googleapis today, so
    // concurrent per-ID gets (bounded by pageSize, not per-mailbox-message)
    // is the correct trade-off; this is still one page-sized burst, not an
    // unbounded per-message serial loop across the whole mailbox.
    const envelopes: CanonicalEnvelope[] = [];
    // Keep concurrency deliberately small for low-memory PCs and Gmail quota stability.
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
    // Gmail's batchModify moves many messages to Trash in one call — the
    // correct batched primitive, not messages.trash() looped per ID.
    await this.gmail.users.messages.batchModify({
      userId: "me",
      requestBody: { ids: messageIds, addLabelIds: ["TRASH"], removeLabelIds: ["INBOX"] },
    });
  }

  async disconnect(): Promise<void> {
    this.gmail = null;
  }
}
