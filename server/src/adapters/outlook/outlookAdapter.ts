import { createHash } from "node:crypto";
import type {
  EmailAdapter,
  FetchPage,
  FolderDescriptor,
  SpamReportResult,
} from "../../canonical/adapter.js";
import type { CanonicalEnvelope, NormalizedFolder } from "../../canonical/envelope.js";
import { refreshMicrosoftAccessToken } from "../../oauth/microsoftOAuth.js";
import { normalizeRawMessage } from "../../util/mimeNormalize.js";

export interface OutlookOAuthCredentials {
  clientId: string;
  refreshToken: string;
  /** Stable Microsoft Graph `/me.id` for guided OAuth sessions. */
  accountId?: string;
  /** Legacy developer-flow compatibility only; guided desktop OAuth is public-client. */
  clientSecret?: string;
  /** Legacy developer-flow compatibility only. Guided OAuth uses the common authority. */
  tenantId?: string;
}

export type OutlookRefreshTokenSink = (refreshToken: string) => Promise<void>;

const GRAPH_BASE = "https://graph.microsoft.com/v1.0";

function normalizeWellKnownFolder(name: string): NormalizedFolder {
  const lower = name.toLowerCase();
  if (lower === "inbox") return "inbox";
  if (lower === "junkemail") return "spam";
  if (lower === "sentitems") return "sent";
  if (lower === "drafts") return "drafts";
  if (lower === "deleteditems") return "trash";
  if (lower === "archive") return "archive";
  return "other";
}

export class OutlookAdapter implements EmailAdapter {
  readonly provider = "outlook" as const;
  private accessToken: string | null = null;
  private accountProof: string | null = null;

  constructor(
    private readonly credentials: OutlookOAuthCredentials,
    private readonly onRefreshTokenRotated?: OutlookRefreshTokenSink,
  ) {}

  private async graphFetch(path: string, init?: RequestInit): Promise<Response> {
    if (!this.accessToken) throw new Error("Not connected");
    return fetch(`${GRAPH_BASE}${path}`, {
      ...init,
      headers: {
        ...(init?.headers ?? {}),
        Authorization: `Bearer ${this.accessToken}`,
        Prefer: 'IdType="ImmutableId"',
      },
    });
  }

  async connect(signal: AbortSignal): Promise<void> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");

    const originalRefreshToken = this.credentials.refreshToken;
    const tokenResult = await refreshMicrosoftAccessToken({
      clientId: this.credentials.clientId,
      refreshToken: originalRefreshToken,
      clientSecret: this.credentials.clientSecret,
    });
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    this.accessToken = tokenResult.accessToken;

    try {
      const meRes = await this.graphFetch("/me?$select=id,mail,userPrincipalName");
      if (!meRes.ok) throw new Error(`Graph profile failed: ${meRes.status}`);
      const me = await meRes.json() as { id?: unknown; mail?: unknown; userPrincipalName?: unknown };
      const graphAccountId = typeof me.id === "string" ? me.id.trim() : "";
      if (!graphAccountId) throw new Error("Microsoft Graph profile did not contain a stable account ID.");
      if (this.credentials.accountId && graphAccountId !== this.credentials.accountId) {
        throw new Error("The protected Outlook credential resolved to a different Microsoft account. Reconnect the account.");
      }

      if (tokenResult.refreshToken !== originalRefreshToken) {
        await this.onRefreshTokenRotated?.(tokenResult.refreshToken);
        this.credentials.refreshToken = tokenResult.refreshToken;
      }
      this.accountProof = createHash("sha256").update(graphAccountId).digest("hex");
    } catch (error) {
      this.accessToken = null;
      this.accountProof = null;
      throw error;
    }
  }

  async listFolders(signal: AbortSignal): Promise<FolderDescriptor[]> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const wellKnown = ["inbox", "junkemail", "sentitems", "drafts", "deleteditems"];
    const results = await Promise.all(
      wellKnown.map(async (name) => {
        const res = await this.graphFetch(`/me/mailFolders/${name}?$select=id,displayName`);
        if (!res.ok) return null;
        const data = await res.json() as { id?: unknown };
        return typeof data.id === "string" && data.id
          ? { id: data.id, wellKnownName: name }
          : null;
      }),
    );
    return results
      .filter((r): r is { id: string; wellKnownName: string } => r !== null)
      .map((r) => {
        const normalized = normalizeWellKnownFolder(r.wellKnownName);
        return { providerFolderName: r.id, normalized, includedByDefault: !["sent", "drafts", "trash"].includes(normalized) };
      });
  }

  async fetchPage(
    folder: FolderDescriptor,
    cursor: string | null,
    pageSize: number,
    signal: AbortSignal,
  ): Promise<FetchPage> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    if (!this.accountProof) throw new Error("Not connected");

    const listPath = cursor ?? `/me/mailFolders/${folder.providerFolderName}/messages?$select=id&$top=${pageSize}&$orderby=receivedDateTime desc`;
    const listRes = cursor && cursor.startsWith("https://graph.microsoft.com/")
      ? await fetch(cursor, {
          headers: {
            Authorization: `Bearer ${this.accessToken}`,
            Prefer: 'IdType="ImmutableId"',
          },
          signal,
          redirect: "error",
        })
      : await this.graphFetch(listPath, { signal });
    if (!listRes.ok) throw new Error(`Graph list failed: ${listRes.status}`);
    const listData = await listRes.json() as { value?: Array<{ id?: unknown }>; "@odata.nextLink"?: unknown };
    const ids = (listData.value ?? [])
      .map((message) => typeof message.id === "string" ? message.id : "")
      .filter(Boolean);

    if (ids.length === 0) return { envelopes: [], nextCursor: null, done: true };

    const envelopes: CanonicalEnvelope[] = [];
    for (let i = 0; i < ids.length; i += 20) {
      if (signal.aborted) throw new DOMException("Aborted", "AbortError");
      const chunk = ids.slice(i, i + 20);
      const batchRes = await this.graphFetch("/$batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          requests: chunk.map((id, idx) => ({
            id: String(idx),
            method: "GET",
            url: `/me/messages/${id}/$value`,
            headers: { Prefer: 'IdType="ImmutableId"' },
          })),
        }),
      });
      if (!batchRes.ok) throw new Error(`Graph batch fetch failed: ${batchRes.status}`);
      const batchData = await batchRes.json() as { responses?: Array<{ id?: unknown; status?: unknown; body?: unknown }> };
      for (const resp of batchData.responses ?? []) {
        if (resp.status !== 200 || typeof resp.body !== "string" || typeof resp.id !== "string") continue;
        const index = Number(resp.id);
        if (!Number.isInteger(index) || index < 0 || index >= chunk.length) continue;
        envelopes.push(
          await normalizeRawMessage(resp.body, {
            provider: "outlook",
            accountProof: this.accountProof,
            providerFolderName: folder.providerFolderName,
            normalizedFolder: folder.normalized,
            providerNativeId: chunk[index]!,
          }),
        );
      }
    }

    const nextLink = typeof listData["@odata.nextLink"] === "string" ? listData["@odata.nextLink"] : undefined;
    return { envelopes, nextCursor: nextLink ?? null, done: !nextLink };
  }

  private async batchMove(
    messageIds: string[],
    destinationId: "deleteditems" | "junkemail",
    signal: AbortSignal,
  ): Promise<number> {
    let moved = 0;
    for (let i = 0; i < messageIds.length; i += 20) {
      if (signal.aborted) throw new DOMException("Aborted", "AbortError");
      const chunk = messageIds.slice(i, i + 20);
      const response = await this.graphFetch("/$batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          requests: chunk.map((id, idx) => ({
            id: String(idx),
            method: "POST",
            url: `/me/messages/${id}/move`,
            body: { destinationId },
            headers: { "Content-Type": "application/json", Prefer: 'IdType="ImmutableId"' },
          })),
        }),
      });
      if (!response.ok) throw new Error(`Graph batch move failed: ${response.status}`);
      const body = await response.json() as { responses?: Array<{ status?: unknown }> };
      const failures = (body.responses ?? []).filter((item) => typeof item.status !== "number" || item.status < 200 || item.status >= 300);
      if (failures.length) {
        throw new Error(`Graph rejected ${failures.length} of ${chunk.length} message move request(s).`);
      }
      moved += chunk.length;
    }
    return moved;
  }

  async moveToTrash(messageIds: string[], signal: AbortSignal): Promise<void> {
    await this.batchMove(messageIds, "deleteditems", signal);
  }

  async reportSpam(messageIds: string[], signal: AbortSignal): Promise<SpamReportResult> {
    const reported = await this.batchMove(messageIds, "junkemail", signal);
    return { requested: messageIds.length, reported, mode: "junk_folder_move" };
  }

  async disconnect(): Promise<void> {
    this.accessToken = null;
    this.accountProof = null;
  }
}
