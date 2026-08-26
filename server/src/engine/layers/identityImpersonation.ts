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
import { extractStructuralScamFacts } from "../structuralScamEvidence.js";
import type { LayerResult } from "../verdict.js";

/**
 * Layer 2 — Identity and impersonation.
 * Local decisions use authenticated organizational structure rather than a
 * compiled company allowlist. Updateable aliases/domains belong to the signed
 * intelligence feed.
 */
export const OFFICIAL_BRAND_DOMAINS: Readonly<Record<string, readonly string[]>> = Object.freeze({});
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
  "account", "alerts", "billing", "care", "customer", "email", "find", "info", "mail",
  "marketing", "message", "news", "newsletter", "notification", "notifications",
  "official", "payments", "promo", "rewards", "security", "service", "services",
  "support", "team", "update", "updates",
]);

const TRANSACTIONAL_CONTEXT = /\b(?:account|bank|billing|card|delivery|invoice|order|password|payment|purchase|refund|reward|security|subscription|tax|transaction|verify|wallet)\b/i;
const ORGANIZATION_CONTEXT = /\b(?:airlines?|association|bank|clinic|college|company|corp(?:oration)?|credit union|department|financial|foundation|group|health|hospital|hotel|inc(?:orporated)?|labs?|limited|llc|ltd|market|payments?|school|services?|shop|store|systems?|team|technolog(?:y|ies)|university)\b/i;
const EXPLICIT_DOMAIN_RE = /(?:^|[^a-z0-9-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})(?=$|[^a-z0-9-])/gi;
const EXPLICIT_DOMAIN_PREFIX = /(?:https?:\/\/|www\.|\b(?:at|domain|from|portal|site|via|website)\s*[:=-]?\s*)$/i;
const EXPLICIT_DOMAIN_SUFFIX = /^\s*(?:domain|portal|site|website)\b/i;

function words(value: string): string[] {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .split(/\s+/)
    .filter((word) => word.length >= 3 && !GENERIC_IDENTITY_WORDS.has(word));
}

/**
 * A dotted token is not automatically a domain claim. Usernames, filenames,
 * product versions, recipient addresses and generated identifiers commonly
 * contain dots. Treat it as an asserted network identity only when nearby
 * syntax explicitly presents it as a URL, domain, site, portal, sender, or
 * destination rather than merely as the domain portion of an email address.
 */
function explicitDomains(value: string): string[] {
  const found = new Set<string>();
  EXPLICIT_DOMAIN_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = EXPLICIT_DOMAIN_RE.exec(value))) {
    const candidate = match[1]!;
    const candidateOffset = match[0].lastIndexOf(candidate);
    const start = match.index + Math.max(0, candidateOffset);
    const end = start + candidate.length;
    const before = value.slice(Math.max(0, start - 48), start);
    const after = value.slice(end, Math.min(value.length, end + 24));
    const explicit = candidate.toLowerCase().startsWith("www.")
      || EXPLICIT_DOMAIN_PREFIX.test(before)
      || EXPLICIT_DOMAIN_SUFFIX.test(after);
    if (explicit) found.add(normalizeDomainName(candidate));
  }
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

function resemblesPersonNotification(displayName: string, sharedWords: string[]): boolean {
  // Many social/contact systems format the sender as “Person Name on Service”
  // or “Person Name via Service”. Treat the leading 2–4 word identity as a
  // person when it is repeated in the subject and contains no organization
  // type cue. This is grammar-based and does not depend on any provider name.
  const match = displayName.trim().match(
    /^([\p{L}\p{M}'’.-]+(?:\s+[\p{L}\p{M}'’.-]+){1,3})\s+(?:on|via)\s+.+$/iu,
  );
  if (!match) return false;
  const leadingWords = words(match[1]!);
  if (leadingWords.length < 2 || leadingWords.length > 4) return false;
  if (ORGANIZATION_CONTEXT.test(match[1]!)) return false;
  return leadingWords.every((word) => sharedWords.includes(word));
}

function repeatedOrganizationClaim(envelope: CanonicalEnvelope): string[] {
  const displayName = envelope.from.displayName ?? "";
  const displayWords = words(displayName);
  if (!displayWords.length) return [];
  const subjectWords = new Set(words(envelope.subject));
  const shared = displayWords.filter((word) => subjectWords.has(word));
  if (!shared.length) return [];
  if (resemblesPersonNotification(displayName, shared)) return [];

  // Structural organization claims are corroborating evidence, not a new
  // prerequisite for this established identity detector. Some valid generic
  // organization phrases appear later in subjects (for example "Your X
  // account...") and intentionally fall outside the extractor's stricter
  // leading-claim grammar. When structural claims do exist, use their overlap
  // to narrow the candidate words; otherwise preserve the prior repeated-word
  // grammar so existing spoof/QR identity evidence cannot silently disappear.
  const structuralFacts = extractStructuralScamFacts({
    subject: envelope.subject,
    text: envelope.textPreview,
    htmlText: null,
    displayName,
    links: envelope.links,
  });
  const structuralClaimWords = new Set(structuralFacts.organizationClaims.flatMap((claim) => words(claim)));
  const structurallySupported = shared.filter((word) => structuralClaimWords.has(word));
  const candidateShared = structurallySupported.length ? structurallySupported : shared;

  // Repeated personal names are common in social/contact notifications. A
  // local generic brand rule must therefore also see transactional/security
  // context or an organization-type cue before treating the repeated words as
  // an organization claim.
  const riskyContext = TRANSACTIONAL_CONTEXT.test(`${envelope.subject} ${envelope.textPreview ?? ""}`);
  const organizationContext = ORGANIZATION_CONTEXT.test(displayName);
  if (!riskyContext && !organizationContext) return [];

  // A single short word is often a product feature or ordinary verb (for
  // example "Find My"), not a reliable organization claim. Require either a
  // multi-word identity or one distinctive word of at least five characters.
  const distinctive = candidateShared.length >= 2
    ? candidateShared
    : candidateShared.filter((word) => word.length >= 5);
  if (!distinctive.length) return [];
  if (!riskyContext && distinctive.length < 2) return [];
  return distinctive;
}

function claimMatchesLabels(claimWords: string[], labels: string[]): boolean {
  return claimWords.some((claim) => labels.some((label) => label.includes(claim) || claim.includes(label)));
}

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
  const relayOrigins = verifiedRelayOriginDomains(envelope);
  const knownRelay = Boolean(senderDomain && isKnownSenderRelay(senderDomain));
  const unprovenRelay = knownRelay && relayOrigins.length === 0;

  if (envelope.replyTo?.domain && senderDomain && !unprovenRelay) {
    const replyDomain = normalizeDomainName(envelope.replyTo.domain);
    const directRelated = !knownRelay && sameOrganizationalDomain(senderDomain, replyDomain);
    const relayAligned = relayOrigins.some((domain) => sameOrganizationalDomain(domain, replyDomain));

    if (!directRelated && !relayAligned) {
      evidence.push({
        layer: "identity_impersonation",
        code: "REPLY_TO_MISMATCH",
        description: `Reply-To domain "${replyDomain}" is unrelated to the sender identity evidence available for this message.`,
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
    const visibleSenderAligned = Boolean(
      senderDomain && !knownRelay && sameOrganizationalDomain(senderDomain, claimed),
    );
    const authenticatedAligned = authenticatedIdentities.some((identity) => sameOrganizationalDomain(identity, claimed));
    const relayAligned = relayOrigins.some((origin) => sameOrganizationalDomain(origin, claimed));
    const aligned = visibleSenderAligned || authenticatedAligned || relayAligned;

    // A known relay with no attributable origin provides uncertainty, not
    // contradictory organization evidence. Conversely, direct unrelated sender
    // domains and proven relay origins can support a real contradiction.
    if (!aligned && senderDomain && !unprovenRelay) {
      const attributableIdentity = authenticatedIdentities[0]
        ?? relayOrigins[0]
        ?? organizationalDomain(senderDomain);
      evidence.push({
        layer: "identity_impersonation",
        code: "EXPLICIT_DOMAIN_CLAIM_MISMATCH",
        description: `Message explicitly claims domain "${claimed}" but the sender identity is "${attributableIdentity}".`,
        scoreContribution: 4,
        source: "local",
      });
      break;
    }
  }

  const claimWords = repeatedOrganizationClaim(envelope);
  const labels = organizationLabels(envelope);
  if (!unprovenRelay && claimWords.length && labels.length && !claimMatchesLabels(claimWords, labels)) {
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

  if (unprovenRelay) {
    return {
      layer: "identity_impersonation",
      applicable: true,
      evidence,
      incomplete: true,
      incompleteReason: "Known relay/forwarder transport was observed, but the original organizational sender identity could not be proven.",
    };
  }

  return { layer: "identity_impersonation", applicable: true, evidence, incomplete: false };
}