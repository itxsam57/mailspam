import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import {
  isKnownSenderRelay,
  normalizeDomainName,
  organizationalDomain,
  sameOrganizationalDomain,
} from "../../util/domainRelation.js";
import {
  authenticatedSenderIdentityDomains,
  hasAuthenticatedOrganizationalIdentity,
  hasDeterministicOfficialIdentity,
  isDirectOfficialSenderDomain,
  isOfficialBrandSender,
  isOfficialPrivateRelaySender,
  messageIdentityCandidateDomains,
  verifiedRelayOriginDomains,
} from "../identitySignals.js";
import type { LayerResult } from "../verdict.js";

/**
 * Layer 2 — Identity and impersonation.
 *
 * The local engine intentionally contains no company/brand allowlist. It uses
 * authenticated organizational domains, Reply-To alignment, relay provenance,
 * explicit domain claims, and organization-like claims repeated in a risky
 * subject. Optional known-brand mappings belong to the signed intelligence
 * feed, where they can be updated without shipping new application code.
 */

/** Deprecated compatibility export. Identity mappings are no longer code data. */
export const OFFICIAL_BRAND_DOMAINS: Readonly<Record<string, readonly string[]>> = Object.freeze({});
/** Deprecated compatibility export. Dynamic identity knowledge lives in the signed feed. */
export function claimedBrandFromText(_text: string): null { return null; }
export function claimedBrandForEnvelope(_envelope: CanonicalEnvelope): null { return null; }

export {
  hasAuthenticatedOrganizationalIdentity,
  hasDeterministicOfficialIdentity,
  isDirectOfficialSenderDomain,
  isOfficialBrandSender,
  isOfficialPrivateRelaySender,
};

const GENERIC_IDENTITY_WORDS = new Set([
  "account", "alerts", "billing", "care", "customer", "email", "info", "mail",
  "marketing", "message", "news", "newsletter", "notification", "notifications",
  "official", "payments", "promo", "rewards", "security", "service", "services",
  "support", "team", "update", "updates",
]);

const TRANSACTIONAL_CONTEXT = /\b(?:account|bank|billing|card|delivery|invoice|order|password|payment|purchase|refund|reward|security|subscription|tax|transaction|verify|wallet)\b/i;
const EXPLICIT_DOMAIN_RE = /(?:^|[^a-z0-9-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})(?=$|[^a-z0-9-])/gi;

function words(value: string): string[] {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .split(/\s+/)
    .filter((word) => word.length >= 3 && !GENERIC_IDENTITY_WORDS.has(word));
}

function explicitDomains(value: string): string[] {
  const found = new Set<string>();
  EXPLICIT_DOMAIN_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = EXPLICIT_DOMAIN_RE.exec(value))) found.add(normalizeDomainName(match[1]!));
  return [...found];
}

function levenshtein(a: string, b: string): number {
  const dp: number[][] = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i]![0] = i;
  for (let j = 0; j <= b.length; j++) dp[0]![j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i]![j] = a[i - 1] === b[j - 1]
        ? dp[i - 1]![j - 1]!
        : 1 + Math.min(dp[i - 1]![j]!, dp[i]![j - 1]!, dp[i - 1]![j - 1]!);
    }
  }
  return dp[a.length]![b.length]!;
}

function organizationLabels(envelope: CanonicalEnvelope): string[] {
  const domains = new Set<string>();
  if (envelope.from.domain && !isKnownSenderRelay(envelope.from.domain)) domains.add(envelope.from.domain);
  for (const domain of messageIdentityCandidateDomains(envelope)) domains.add(domain);
  for (const domain of authenticatedSenderIdentityDomains(envelope)) domains.add(domain);
  for (const domain of verifiedRelayOriginDomains(envelope)) domains.add(domain);

  const labels = new Set<string>();
  for (const domain of domains) {
    const organization = organizationalDomain(domain);
    const label = organization.split(".")[0]?.replace(/[^a-z0-9]/g, "");
    if (label && label.length >= 3) labels.add(label);
  }
  return [...labels];
}

function repeatedOrganizationClaim(envelope: CanonicalEnvelope): string[] {
  const displayWords = words(envelope.from.displayName ?? "");
  if (!displayWords.length) return [];
  const subjectWords = new Set(words(envelope.subject));
  const shared = displayWords.filter((word) => subjectWords.has(word));
  if (!shared.length) return [];

  const riskyContext = TRANSACTIONAL_CONTEXT.test(`${envelope.subject} ${envelope.textPreview ?? ""}`);
  if (!riskyContext && shared.length < 2) return [];
  return shared;
}

function claimMatchesLabels(claimWords: string[], labels: string[]): boolean {
  return claimWords.some((claim) => labels.some((label) => label.includes(claim) || claim.includes(label)));
}

/**
 * Authentication proves who owns the sending domain, not that the visible
 * organization claim is true. This extra gate prevents an authenticated
 * attacker domain from receiving the same trust as an aligned organization.
 */
export function organizationClaimAligned(envelope: CanonicalEnvelope): boolean {
  const claimWords = repeatedOrganizationClaim(envelope);
  if (!claimWords.length) return true;
  const labels = organizationLabels(envelope);
  return labels.length > 0 && claimMatchesLabels(claimWords, labels);
}

export function identityImpersonationLayer(envelope: CanonicalEnvelope): LayerResult {
  const evidence: LayerResult["evidence"] = [];
  const senderDomain = envelope.from.domain ? normalizeDomainName(envelope.from.domain) : null;
  const authenticatedIdentities = authenticatedSenderIdentityDomains(envelope);

  if (envelope.replyTo?.domain && senderDomain) {
    const replyDomain = normalizeDomainName(envelope.replyTo.domain);
    const related = sameOrganizationalDomain(senderDomain, replyDomain);
    const relayOrigins = verifiedRelayOriginDomains(envelope);
    const relayAligned = relayOrigins.some((domain) => sameOrganizationalDomain(domain, replyDomain));

    if (!related && !relayAligned) {
      evidence.push({
        layer: "identity_impersonation",
        code: "REPLY_TO_MISMATCH",
        description: `Reply-To domain "${replyDomain}" is unrelated to the authenticated sender identity.`,
        scoreContribution: 2,
        source: "local",
      });
    }
  }

  const claimedDomains = new Set([
    ...explicitDomains(envelope.from.displayName ?? ""),
    ...explicitDomains(envelope.subject),
  ]);
  for (const claimed of claimedDomains) {
    const aligned = authenticatedIdentities.some((identity) => sameOrganizationalDomain(identity, claimed));
    if (!aligned && senderDomain && !isKnownSenderRelay(senderDomain)) {
      evidence.push({
        layer: "identity_impersonation",
        code: "EXPLICIT_DOMAIN_CLAIM_MISMATCH",
        description: `Message explicitly claims domain "${claimed}" but the sender identity is "${organizationalDomain(senderDomain)}".`,
        scoreContribution: 4,
        source: "local",
      });
      break;
    }
  }

  const claimWords = repeatedOrganizationClaim(envelope);
  const labels = organizationLabels(envelope);
  if (claimWords.length && labels.length && !claimMatchesLabels(claimWords, labels)) {
    const closest = Math.min(...claimWords.flatMap((claim) => labels.map((label) => levenshtein(claim, label))));
    const lookalike = closest > 0 && closest <= 2 && claimWords.some((word) => word.length >= 5);
    evidence.push({
      layer: "identity_impersonation",
      code: lookalike ? "BRAND_LOOKALIKE_DOMAIN" : "BRAND_DOMAIN_MISMATCH",
      description: `Organization-like identity claim "${claimWords.join(" ")}" is not supported by the sender or message identity domains.`,
      scoreContribution: lookalike ? 5 : 4,
      source: "local",
    });
  }

  return { layer: "identity_impersonation", applicable: true, evidence, incomplete: false };
}
