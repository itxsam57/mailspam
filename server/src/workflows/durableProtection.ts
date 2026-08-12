import type { EmailAdapter } from "../canonical/adapter.js";
import type { ScanResult } from "../engine/pipeline.js";

export const MAX_DURABLE_AUTO_TRASH_IDS = 5_000;
export const DURABLE_AUTO_TRASH_BATCH_SIZE = 100;

const DURABLE_AUTO_TRASH_EVIDENCE = new Set([
  "BLOCKED_SENDER",
  "BLOCKED_DOMAIN",
  "LOCALLY_REPORTED_SCAM_CAMPAIGN",
  "GLOBAL_CONFIRMED_MATCH",
]);

export class DurableProtectionEnforcementError extends Error {
  constructor(
    message: string,
    readonly requested: number,
    readonly moved: number,
  ) {
    super(message);
    this.name = "DurableProtectionEnforcementError";
  }
}

export function isDurableAutoTrashResult(result: ScanResult): boolean {
  return result.scored.verdict === "confirmed_threat" &&
    result.scored.evidence.some((item) => DURABLE_AUTO_TRASH_EVIDENCE.has(item.code));
}

export function collectDurableAutoTrashIds(
  results: Iterable<ScanResult>,
  target: Set<string>,
  maximum = MAX_DURABLE_AUTO_TRASH_IDS,
): void {
  for (const result of results) {
    if (!isDurableAutoTrashResult(result)) continue;
    const providerNativeId = result.envelope.providerNativeId?.trim();
    if (!providerNativeId || target.has(providerNativeId)) continue;
    if (target.size >= maximum) {
      throw new DurableProtectionEnforcementError(
        `Automatic Trash protection exceeded the bounded limit of ${maximum} messages in one scan. No provider mutation was started for the overflowing message.`,
        target.size + 1,
        0,
      );
    }
    target.add(providerNativeId);
  }
}

/**
 * Enforce a durable protection decision only after mailbox enumeration ends.
 * Calls are deliberately bounded because providers differ in mutation batch
 * limits. Trash is reversible through the provider mailbox; this function
 * never performs permanent deletion.
 */
export async function enforceDurableAutoTrash(
  adapter: Pick<EmailAdapter, "moveToTrash">,
  providerNativeIds: Iterable<string>,
  signal: AbortSignal,
  batchSize = DURABLE_AUTO_TRASH_BATCH_SIZE,
): Promise<{ requested: number; moved: number }> {
  const ids = [...new Set([...providerNativeIds].map((value) => value.trim()).filter(Boolean))];
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > DURABLE_AUTO_TRASH_BATCH_SIZE) {
    throw new Error(`Durable protection batch size must be between 1 and ${DURABLE_AUTO_TRASH_BATCH_SIZE}.`);
  }
  if (ids.length > MAX_DURABLE_AUTO_TRASH_IDS) {
    throw new DurableProtectionEnforcementError(
      `Automatic Trash protection exceeded the bounded limit of ${MAX_DURABLE_AUTO_TRASH_IDS} messages in one scan.`,
      ids.length,
      0,
    );
  }

  let moved = 0;
  for (let offset = 0; offset < ids.length; offset += batchSize) {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const batch = ids.slice(offset, offset + batchSize);
    try {
      await adapter.moveToTrash(batch, signal);
      moved += batch.length;
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new DurableProtectionEnforcementError(
        `Automatic Trash protection moved ${moved} of ${ids.length} confirmed messages before the provider rejected the next bounded batch: ${reason}`,
        ids.length,
        moved,
      );
    }
  }
  return { requested: ids.length, moved };
}
