import type { EmailAdapter } from "../canonical/adapter.js";
import type { CanonicalEnvelope } from "../canonical/envelope.js";
import type { InMemoryPersonalPolicyStore } from "../engine/layers/personalRules.js";

/**
 * One-click block (spec Section 5/7 response policy: high_risk and
 * confirmed_threat verdicts unlock this). Blocking is always local personal
 * policy first — it never depends on the mailbox move succeeding, so a user
 * is protected on future scans even if the provider trash call fails.
 */
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

/**
 * Bulk move-to-trash for confirmed_threat / user-approved high_risk
 * messages. Never deletes irrecoverably — moveToTrash on every adapter
 * contract is a reversible provider Trash move, never a permanent purge
 * (spec: user must be able to recover from Trash per normal provider UI).
 *
 * `providerNativeIds` must be `envelope.providerNativeId` values, NOT the
 * canonical `envelope.messageId` (RFC822 Message-ID) — the two are
 * different identifiers; only providerNativeId round-trips through the
 * adapter's action APIs.
 */
export async function moveMessagesToTrash(
  adapter: EmailAdapter,
  providerNativeIds: string[],
  signal: AbortSignal
): Promise<CleanupResult> {
  const result: CleanupResult = { requested: providerNativeIds.length, moved: 0, failed: [] };
  // Batch, not one call per message — spec explicitly calls out N+1 provider calls as a regression.
  try {
    await adapter.moveToTrash(providerNativeIds, signal);
    result.moved = providerNativeIds.length;
  } catch (err) {
    for (const id of providerNativeIds) {
      result.failed.push({ messageId: id, reason: (err as Error).message });
    }
  }
  return result;
}
