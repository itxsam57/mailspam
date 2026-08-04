import type { EmailAdapter } from "../canonical/adapter.js";
import type { CanonicalEnvelope } from "../canonical/envelope.js";
import type { InMemoryPersonalPolicyStore } from "../engine/layers/personalRules.js";

export function blockSender(store: InMemoryPersonalPolicyStore, envelope: CanonicalEnvelope) {
  if (envelope.from.address) store.blockSender(envelope.from.address);
}

export function blockDomain(store: InMemoryPersonalPolicyStore, envelope: CanonicalEnvelope) {
  if (envelope.from.domain) store.blockDomain(envelope.from.domain);
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
