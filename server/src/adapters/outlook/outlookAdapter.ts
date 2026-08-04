import { ConfidentialClientApplication } from "@azure/msal-node";
import { createHash } from "node:crypto";
import type { EmailAdapter, FetchPage, FolderDescriptor } from "../../canonical/adapter.js";
import type { CanonicalEnvelope, NormalizedFolder } from "../../canonical/envelope.js";
import { normalizeRawMessage } from "../../util/mimeNormalize.js";

export interface OutlookOAuthCredentials {
  clientId: string;
  clientSecret: string;
  tenantId: string;
  refreshToken: string;
}

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

/**
 * Outlook adapter (spec Section 3): OAuth via MSAL, Microsoft Graph REST.
 * Uses Graph's $batch endpoint to fetch a page of message bodies in one
 * HTTP round trip — the same "batch, not per-message" requirement as
 * Gmail/IMAP (spec regression 12.3).
 *
 * Required scope: Mail.ReadWrite (read is enough for scanning; write is
 * only exercised for the explicit Trash-move action).
 */
export class OutlookAdapter implements EmailAdapter {
  readonly provider = "outlook" as const;
  private credentials: OutlookOAuthCredentials;
  private msal: ConfidentialClientApplication;
  private accessToken: string | null = null;
  private accountProof: string | null = null;

  constructor(credentials: OutlookOAuthCredentials) {
    this.credentials = credentials;
    this.msal = new ConfidentialClientApplication({
      auth: {
        clientId: credentials.clientId,
        clientSecret: credentials.clientSecret,
        authority: `https://login.microsoftonline.com/${credentials.tenantId}`,
      },
    });
  }

  private async graphFetch(path: string, init?: RequestInit): Promise<Response> {
    if (!this.accessToken) throw new Error("Not connected");
    return fetch(`${GRAPH_BASE}${path}`, {
      ...init,
      headers: { ...(init?.headers ?? {}), Authorization: `Bearer ${this.accessToken}` },
    });
  }

  async connect(signal: AbortSignal): Promise<void> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const result = await this.msal.acquireTokenByRefreshToken({
      refreshToken: this.credentials.refreshToken,
      scopes: ["https://graph.microsoft.com/Mail.ReadWrite"],
    });
    if (!result?.accessToken) throw new Error("Failed to acquire Graph access token.");
    this.accessToken = result.accessToken;

    const meRes = await this.graphFetch("/me?$select=mail,userPrincipalName");
    const me = await meRes.json();
    const identity = me.mail ?? me.userPrincipalName ?? "unknown";
    this.accountProof = createHash("sha256").update(identity).digest("hex");
  }

  async listFolders(signal: AbortSignal): Promise<FolderDescriptor[]> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const wellKnown = ["inbox", "junkemail", "sentitems", "drafts", "deleteditems"];
    // mailFolders/{id} accepts well-known folder names directly — metadata-only, no content download.
    const results = await Promise.all(
      wellKnown.map(async (name) => {
        const res = await this.graphFetch(`/me/mailFolders/${name}?$select=id,displayName`);
        if (!res.ok) return null;
        const data = await res.json();
        return { id: data.id as string, wellKnownName: name };
      })
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
    signal: AbortSignal
  ): Promise<FetchPage> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    if (!this.accountProof) throw new Error("Not connected");

    const listPath = cursor ?? `/me/mailFolders/${folder.providerFolderName}/messages?$select=id&$top=${pageSize}&$orderby=receivedDateTime desc`;
    const listRes = cursor && cursor.startsWith("https://")
      ? await fetch(cursor, { headers: { Authorization: `Bearer ${this.accessToken}` }, signal })
      : await this.graphFetch(listPath, { signal });
    if (!listRes.ok) throw new Error(`Graph list failed: ${listRes.status}`);
    const listData = await listRes.json();
    const ids: string[] = (listData.value ?? []).map((m: { id: string }) => m.id);

    if (ids.length === 0) return { envelopes: [], nextCursor: null, done: true };

    // Graph $batch: up to 20 sub-requests per call. Chunk the page into
    // batches of 20 rather than issuing one HTTP request per message.
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
            url: `/me/messages/${id}/$value`, // MIME (.eml) content
          })),
        }),
      });
      const batchData = await batchRes.json();
      for (const resp of batchData.responses ?? []) {
        if (resp.status !== 200) continue;
        // Graph returns raw MIME as text for the $value endpoint.
        envelopes.push(
          await normalizeRawMessage(resp.body as string, {
            provider: "outlook",
            accountProof: this.accountProof,
            providerFolderName: folder.providerFolderName,
            normalizedFolder: folder.normalized,
            providerNativeId: chunk[Number(resp.id)]!,
          })
        );
      }
    }

    const nextLink: string | undefined = listData["@odata.nextLink"];
    // Microsoft continuation URLs are opaque. Store/reuse the complete URL unchanged.
    return { envelopes, nextCursor: nextLink ?? null, done: !nextLink };
  }

  async moveToTrash(messageIds: string[], signal: AbortSignal): Promise<void> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    // Graph has no bulk-move endpoint; batch the individual move calls
    // through $batch (still one HTTP round trip per 20 messages, not one
    // per message).
    for (let i = 0; i < messageIds.length; i += 20) {
      if (signal.aborted) throw new DOMException("Aborted", "AbortError");
      const chunk = messageIds.slice(i, i + 20);
      await this.graphFetch("/$batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          requests: chunk.map((id, idx) => ({
            id: String(idx),
            method: "POST",
            url: `/me/messages/${id}/move`,
            body: { destinationId: "deleteditems" },
            headers: { "Content-Type": "application/json" },
          })),
        }),
      });
    }
  }

  async disconnect(): Promise<void> {
    this.accessToken = null;
  }
}
