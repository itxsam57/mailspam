import type { SignedFeedEntry } from "../engine/layers/globalIntelligence.js";
import type { FamilyThreatSnapshot } from "./accountFamilyTypes.js";
import { FAMILY_FEED_RULE_PREFIX } from "./familyThreatProtocol.js";

/**
 * Converts a privacy-reduced, already-authenticated Family Shield snapshot into
 * the same portable intelligence entry shape consumed by the shared scanner.
 * No sender, subject, body, mailbox identity, URL, attachment or provider ID is
 * introduced here; the campaign fingerprint is the only matching key.
 */
export function familyThreatSnapshotToFeedEntries(snapshot: FamilyThreatSnapshot | null | undefined): SignedFeedEntry[] {
  if (!snapshot) return [];
  return snapshot.entries
    .filter((entry) => entry.status === "warning" || entry.status === "confirmed")
    .map((entry) => ({
      type: "campaign" as const,
      value: entry.campaignFingerprint,
      confirmedThreat: entry.status === "confirmed",
      ruleId: `${FAMILY_FEED_RULE_PREFIX}${snapshot.familyCircleId}:${entry.status}`,
    }));
}

export function mergeVerifiedAndFamilyIntelligence(
  verifiedEntries: SignedFeedEntry[] | null,
  familySnapshot: FamilyThreatSnapshot | null | undefined,
): SignedFeedEntry[] | null {
  // A broken/expired global signed feed remains unavailable even when Family
  // Shield is healthy. Family data must never hide that fail-closed condition.
  if (verifiedEntries === null) return null;
  return [...verifiedEntries, ...familyThreatSnapshotToFeedEntries(familySnapshot)];
}
