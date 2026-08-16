import type { Provider } from "../canonical/envelope.js";

const IMAP_FAMILY_PROVIDERS = new Set<Provider>(["icloud", "yahoo", "imap"]);
const DEFAULT_PAGE_SIZE = 20;
const IMAP_FAMILY_PAGE_SIZE = 2;
const IMAP_FAMILY_QUICK_LIMIT = 10;

export interface ScanBatchPolicy {
  pageSize: number;
  maxMessages: number | undefined;
}

function positiveInteger(value: number | undefined, fallback: number): number {
  return Number.isFinite(value) && Number(value) > 0
    ? Math.max(1, Math.trunc(Number(value)))
    : fallback;
}

/**
 * Authoritative scan execution policy.
 *
 * HTTP routes may request smaller batches, but they cannot increase the live
 * IMAP-family execution boundary. This prevents restored sessions, legacy
 * routes, background protection, or future callers from silently turning an
 * iCloud/Yahoo/generic-IMAP scan back into a 10/20-message provider batch.
 */
export function resolveScanBatchPolicy(
  provider: Provider,
  type: "quick" | "full" | "spam",
  requestedPageSize?: number,
  requestedMaxMessages?: number,
): ScanBatchPolicy {
  const requestedPage = positiveInteger(requestedPageSize, DEFAULT_PAGE_SIZE);

  if (IMAP_FAMILY_PROVIDERS.has(provider)) {
    const pageSize = Math.min(requestedPage, IMAP_FAMILY_PAGE_SIZE);
    const maxMessages = type === "quick"
      ? Math.min(positiveInteger(requestedMaxMessages, IMAP_FAMILY_QUICK_LIMIT), IMAP_FAMILY_QUICK_LIMIT)
      : undefined;
    return { pageSize, maxMessages };
  }

  return {
    pageSize: requestedPage,
    maxMessages: type === "quick"
      ? positiveInteger(requestedMaxMessages, requestedPage)
      : undefined,
  };
}
