import type { FetchPage, FolderDescriptor } from "../../canonical/adapter.js";
import { ImapAdapter as ImapTransportAdapter } from "./imapTransportAdapter.js";

export * from "./imapTransportAdapter.js";

/**
 * Hard provider-side body/metadata batch ceiling for live IMAP-family accounts.
 * Upstream workflow sizing is advisory; this boundary is authoritative so a
 * stale/misclassified session can never turn an iCloud/Yahoo/IMAP page into a
 * 20-message content fetch.
 */
export const MAX_IMAP_PROVIDER_PAGE_SIZE = 2;

export class ImapAdapter extends ImapTransportAdapter {
  override async fetchPage(
    folder: FolderDescriptor,
    cursorValue: string | null,
    pageSize: number,
    signal: AbortSignal,
  ): Promise<FetchPage> {
    const requested = Number.isFinite(pageSize) ? Math.trunc(pageSize) : 1;
    const boundedPageSize = Math.max(1, Math.min(requested, MAX_IMAP_PROVIDER_PAGE_SIZE));
    return super.fetchPage(folder, cursorValue, boundedPageSize, signal);
  }
}
