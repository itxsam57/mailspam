import type { EmailAdapter } from "../canonical/adapter.js";
import type { ScanResult } from "../engine/pipeline.js";

export const MAX_DURABLE_AUTO_TRASH_IDS = 5_000;
export const MAX_COMMUNITY_WARNING_QUARANTINE_IDS = 5_000;
export const DURABLE_PROTECTION_BATCH_SIZE = 100;

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

export class CommunityWarningQuarantineError extends Error {
  constructor(
    message: string,
    readonly requested: number,
    readonly quarantined: number,
  ) {
    super(message);
    this.name = "CommunityWarningQuarantineError";
  }
}

export function isDurableAutoTrashResult(result: ScanResult): boolean {
  return result.scored.verdict === "confirmed_threat" &&
    result.scored.evidence.some((item) => DURABLE_AUTO_TRASH_EVIDENCE.has(item.code));
}

export function isCommunityWarningQuarantineResult(result: ScanResult): boolean {
  if (result.envelope.folder === "spam" || result.envelope.folder === "trash") return false;
  if (result.scored.verdict === "confirmed_threat") return false;
  return result.scored.evidence.some((item) => item.code === "GLOBAL_WARNING_MATCH");
}

function collectProviderIds(
  results: Iterable<ScanResult>,
  target: Set<string>,
  predicate: (result: ScanResult) => boolean,
  maximum: number,
  errorFactory: (requested: number) => Error,
): void {
  for (const result of results) {
    if (!predicate(result)) continue;
    const providerNativeId = result.envelope.providerNativeId?.trim();
    if (!providerNativeId || target.has(providerNativeId)) continue;
    if (target.size >= maximum) throw errorFactory(target.size + 1);
    target.add(providerNativeId);
  }
}

export function collectDurableAutoTrashIds(
  results: Iterable<ScanResult>,
  target: Set<string>,
  maximum = MAX_DURABLE_AUTO_TRASH_IDS,
): void {
  collectProviderIds(
    results,
    target,
    isDurableAutoTrashResult,
    maximum,
    (requested) => new DurableProtectionEnforcementError(
      `Automatic Trash protection exceeded the bounded limit of ${maximum} messages in one scan. No provider mutation was started for the overflowing message.`,
      requested,
      0,
    ),
  );
}

export function collectCommunityWarningQuarantineIds(
  results: Iterable<ScanResult>,
  target: Set<string>,
  maximum = MAX_COMMUNITY_WARNING_QUARANTINE_IDS,
): void {
  collectProviderIds(
    results,
    target,
    isCommunityWarningQuarantineResult,
    maximum,
    (requested) => new CommunityWarningQuarantineError(
      `Signed-warning quarantine exceeded the bounded limit of ${maximum} messages in one scan. No provider mutation was started for the overflowing message.`,
      requested,
      0,
    ),
  );
}

function normalizedIds(providerNativeIds: Iterable<string>, maximum: number): string[] {
  const ids = [...new Set([...providerNativeIds].map((value) => value.trim()).filter(Boolean))];
  if (ids.length > maximum) throw new Error(`Provider protection set exceeds the bounded limit of ${maximum} messages.`);
  return ids;
}

function validateBatchSize(batchSize: number): void {
  if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > DURABLE_PROTECTION_BATCH_SIZE) {
    throw new Error(`Protection batch size must be between 1 and ${DURABLE_PROTECTION_BATCH_SIZE}.`);
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
  batchSize = DURABLE_PROTECTION_BATCH_SIZE,
): Promise<{ requested: number; moved: number }> {
  validateBatchSize(batchSize);
  const ids = normalizedIds(providerNativeIds, MAX_DURABLE_AUTO_TRASH_IDS);
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

/**
 * Reversibly quarantine only cryptographically verified community warnings.
 * Local heuristics cannot reach this function. The provider's native Spam/Junk
 * action is used so a non-reporting user does not see a warning-level campaign
 * as ordinary Inbox mail while the campaign is still below global-confirmed.
 */
export async function enforceCommunityWarningQuarantine(
  adapter: Pick<EmailAdapter, "reportSpam">,
  providerNativeIds: Iterable<string>,
  signal: AbortSignal,
  batchSize = DURABLE_PROTECTION_BATCH_SIZE,
): Promise<{ requested: number; quarantined: number }> {
  validateBatchSize(batchSize);
  const ids = normalizedIds(providerNativeIds, MAX_COMMUNITY_WARNING_QUARANTINE_IDS);
  let quarantined = 0;
  for (let offset = 0; offset < ids.length; offset += batchSize) {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const batch = ids.slice(offset, offset + batchSize);
    try {
      const result = await adapter.reportSpam(batch, signal);
      if (result.requested !== batch.length || result.reported !== batch.length) {
        throw new Error(`provider confirmed ${result.reported} of ${batch.length}`);
      }
      quarantined += batch.length;
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      throw new CommunityWarningQuarantineError(
        `Signed-warning quarantine moved ${quarantined} of ${ids.length} messages before the provider rejected the next bounded batch: ${reason}`,
        ids.length,
        quarantined,
      );
    }
  }
  return { requested: ids.length, quarantined };
}
