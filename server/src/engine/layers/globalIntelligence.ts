import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import type { LayerResult } from "../verdict.js";

/**
 * Layer 9 — Global verified intelligence (spec Section 5 + 10).
 * Matches against a locally cached, Ed25519-signed threat feed. Full
 * publishing/rotation/rollback pipeline is Milestone 2 scope (spec
 * Section 11); Milestone 1 only needs the *client-side match + signature
 * verification* so the engine has somewhere real to plug the feed in.
 */

export interface SignedFeedEntry {
  type: "sender" | "domain" | "url" | "attachment_hash";
  value: string;
  confirmedThreat: boolean; // false => "warning" tier, true => "confirmed" tier
  ruleId: string;
}

export interface ThreatFeedCache {
  /** Returns null if the cache itself failed signature verification (never trust unsigned/stale data). */
  getVerifiedEntries(): SignedFeedEntry[] | null;
}

export function globalIntelligenceLayer(
  envelope: CanonicalEnvelope,
  feed: ThreatFeedCache
): { result: LayerResult; confirmedByGlobalRule: boolean } {
  const entries = feed.getVerifiedEntries();
  const evidence: LayerResult["evidence"] = [];
  let confirmed = false;

  if (entries === null) {
    return {
      result: {
        layer: "global_intelligence",
        applicable: true,
        evidence: [],
        incomplete: true,
        incompleteReason: "Threat feed failed signature verification or is stale; treated as unavailable, never as 'clean'.",
        blocksSafeVerdict: true,
      },
      confirmedByGlobalRule: false,
    };
  }

  const address = envelope.from.address?.toLowerCase() ?? "";
  const domain = envelope.from.domain?.toLowerCase() ?? "";
  const linkUrls = envelope.links.map((l) => l.normalizedUrl.toLowerCase());
  const attachmentHashes = envelope.attachments.map((a) => a.sha256).filter((h): h is string => !!h);

  for (const entry of entries) {
    let hit = false;
    if (entry.type === "sender" && entry.value.toLowerCase() === address) hit = true;
    if (entry.type === "domain" && entry.value.toLowerCase() === domain) hit = true;
    if (entry.type === "url" && linkUrls.includes(entry.value.toLowerCase())) hit = true;
    if (entry.type === "attachment_hash" && attachmentHashes.includes(entry.value.toLowerCase())) hit = true;

    if (hit) {
      if (entry.confirmedThreat) confirmed = true;
      evidence.push({
        layer: "global_intelligence",
        code: entry.confirmedThreat ? "GLOBAL_CONFIRMED_MATCH" : "GLOBAL_WARNING_MATCH",
        description: `Matched signed threat-feed rule ${entry.ruleId} (${entry.type}).`,
        scoreContribution: entry.confirmedThreat ? 10 : 3,
        source: "signed_feed",
      });
    }
  }

  return {
    result: { layer: "global_intelligence", applicable: true, evidence, incomplete: false },
    confirmedByGlobalRule: confirmed,
  };
}
