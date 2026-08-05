import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import {
  authenticationPassed,
  authenticatedSenderIdentityDomains,
  relayLocalPartEncodesDomain,
} from "../identitySignals.js";
import { isKnownSenderRelay, organizationalDomain, sameOrganizationalDomain } from "../../util/domainRelation.js";
import type { LayerResult } from "../verdict.js";

export interface SignedThreatIndicatorEntry {
  type: "sender" | "domain" | "url" | "attachment_hash";
  value: string;
  confirmedThreat: boolean;
  ruleId: string;
}

/**
 * Updateable identity knowledge. Aliases and domains are data in the verified
 * feed, never compiled into the detector. One entry can describe any company,
 * public body, university, bank, shop, or online service.
 */
export interface SignedIdentityEntry {
  type: "identity";
  value: string;
  aliases: string[];
  domains: string[];
  confirmedThreat: false;
  ruleId: string;
}

export type SignedFeedEntry = SignedThreatIndicatorEntry | SignedIdentityEntry;

export interface ThreatFeedCache {
  /** Returns null if signature verification or freshness checks failed. */
  getVerifiedEntries(): SignedFeedEntry[] | null;
}

function aliasAppears(text: string, alias: string): boolean {
  const normalized = alias.trim().toLowerCase();
  if (!normalized) return false;
  if (normalized.length === 1) return text.trim().toLowerCase() === normalized;
  const escaped = normalized.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(?<![a-z0-9])${escaped}(?![a-z0-9])`, "i").test(text);
}

function verifiedIdentityEntryMatchesSender(envelope: CanonicalEnvelope, entry: SignedIdentityEntry): boolean {
  const allowed = entry.domains.map(organizationalDomain).filter(Boolean);
  const structural = authenticatedSenderIdentityDomains(envelope);
  if (structural.some((identity) => allowed.some((domain) => sameOrganizationalDomain(identity, domain)))) return true;

  if (
    authenticationPassed(envelope) &&
    envelope.from.address &&
    envelope.from.domain &&
    isKnownSenderRelay(envelope.from.domain)
  ) {
    return allowed.some((domain) => relayLocalPartEncodesDomain(envelope.from.address!, domain));
  }
  return false;
}

export function globalIntelligenceLayer(
  envelope: CanonicalEnvelope,
  feed: ThreatFeedCache,
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
        incompleteReason: "Signed intelligence failed verification or freshness checks; treated as unavailable, never as clean.",
        blocksSafeVerdict: true,
      },
      confirmedByGlobalRule: false,
    };
  }

  const address = envelope.from.address?.toLowerCase() ?? "";
  const domain = envelope.from.domain?.toLowerCase() ?? "";
  const linkUrls = envelope.links.map((link) => link.normalizedUrl.toLowerCase());
  const attachmentHashes = envelope.attachments.map((attachment) => attachment.sha256).filter((hash): hash is string => Boolean(hash));
  const identityText = `${envelope.from.displayName ?? ""}\n${envelope.subject}`;

  for (const entry of entries) {
    if (entry.type === "identity") {
      const aliases = [...new Set([entry.value, ...entry.aliases])];
      const claimed = aliases.some((alias) => aliasAppears(identityText, alias));
      if (claimed && !verifiedIdentityEntryMatchesSender(envelope, entry)) {
        evidence.push({
          layer: "global_intelligence",
          code: "SIGNED_IDENTITY_DOMAIN_MISMATCH",
          description: `Identity claim "${entry.value}" is not aligned with the domains in signed rule ${entry.ruleId}.`,
          scoreContribution: 4,
          source: "signed_feed",
        });
      }
      continue;
    }

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
        description: `Matched signed intelligence rule ${entry.ruleId} (${entry.type}).`,
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
