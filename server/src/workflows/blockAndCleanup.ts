import type { EmailAdapter } from "../canonical/adapter.js";
import type { CanonicalEnvelope } from "../canonical/envelope.js";
import type { InMemoryPersonalPolicyStore } from "../engine/layers/personalRules.js";

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const DOMAIN_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

export function normalizeSenderAddress(input: unknown): string {
  if (typeof input !== "string") throw new Error("Sender address must be a string.");
  const value = input.trim().toLowerCase();
  if (!value || value.length > 320 || !EMAIL_PATTERN.test(value)) {
    throw new Error("A valid sender email address is required.");
  }
  return value;
}

export function normalizeSenderDomain(input: unknown): string {
  if (typeof input !== "string") throw new Error("Sender domain must be a string.");
  const value = input.trim().toLowerCase().replace(/^@/, "").replace(/\.$/, "");
  if (!value || !DOMAIN_PATTERN.test(value)) {
    throw new Error("A valid sender domain is required.");
  }
  return value;
}

export function blockSender(store: InMemoryPersonalPolicyStore, envelope: CanonicalEnvelope) {
  if (envelope.from.address) store.blockSender(normalizeSenderAddress(envelope.from.address));
}

export function blockDomain(store: InMemoryPersonalPolicyStore, envelope: CanonicalEnvelope) {
  if (envelope.from.domain) store.blockDomain(normalizeSenderDomain(envelope.from.domain));
}

export interface CleanupResult {
  requested: number;
  moved: number;
  failed: Array<{ messageId: string; reason: string }>;
}

export function normalizeProviderNativeIds(input: unknown, maxBatchSize = 100): string[] {
  if (!Array.isArray(input)) {
    throw new Error("providerNativeIds must be an array.");
  }
  if (input.length === 0) {
    throw new Error("At least one provider message identifier is required.");
  }
  if (input.length > maxBatchSize) {
    throw new Error(`A maximum of ${maxBatchSize} messages can be moved at once.`);
  }

  const normalized: string[] = [];
  const seen = new Set<string>();
  for (const value of input) {
    if (typeof value !== "string" || !value.trim()) {
      throw new Error("Every provider message identifier must be a non-empty string.");
    }
    const id = value.trim();
    if (!seen.has(id)) {
      seen.add(id);
      normalized.push(id);
    }
  }
  return normalized;
}

/**
 * Moves messages to the provider Trash folder in one batch. This is
 * reversible through the provider mailbox and never performs a permanent
 * deletion. Identifiers are providerNativeId values, not RFC Message-IDs.
 */
export async function moveMessagesToTrash(
  adapter: EmailAdapter,
  providerNativeIds: unknown,
  signal: AbortSignal,
): Promise<CleanupResult> {
  const ids = normalizeProviderNativeIds(providerNativeIds);
  const result: CleanupResult = { requested: ids.length, moved: 0, failed: [] };

  try {
    await adapter.moveToTrash(ids, signal);
    result.moved = ids.length;
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    for (const id of ids) result.failed.push({ messageId: id, reason });
  }
  return result;
}
