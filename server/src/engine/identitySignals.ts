import type { CanonicalEnvelope, LinkInfo } from "../canonical/envelope.js";
import {
  isKnownSenderRelay,
  normalizeDomainName,
  organizationalDomain,
  sameOrganizationalDomain,
} from "../util/domainRelation.js";

/** Shared consumer mailboxes authenticate the mailbox provider, not a business identity. */
const SHARED_MAILBOX_DOMAINS = new Set([
  "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com",
  "icloud.com", "me.com", "mac.com", "yahoo.com", "aol.com", "mail.com",
  "gmx.com", "gmx.net", "proton.me", "protonmail.com", "yandex.com",
]);

const DOMAIN_RE = /(?:^|[^a-z0-9-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})(?=$|[^a-z0-9-])/gi;

export function authenticationPassed(envelope: CanonicalEnvelope): boolean {
  const auth = envelope.authentication;
  return auth.dmarc === "pass" || auth.dkim === "pass" || auth.spf === "pass";
}

export function isSharedMailboxDomain(domain: string): boolean {
  return SHARED_MAILBOX_DOMAINS.has(normalizeDomainName(domain));
}

function domainsInText(text: string | null | undefined): string[] {
  if (!text) return [];
  const found: string[] = [];
  let match: RegExpExecArray | null;
  DOMAIN_RE.lastIndex = 0;
  while ((match = DOMAIN_RE.exec(text))) {
    const domain = normalizeDomainName(match[1]!);
    if (domain) found.push(domain);
  }
  return found;
}

function domainsFromUnsubscribe(raw: string | null): string[] {
  if (!raw) return [];
  const found = new Set<string>();
  for (const match of raw.matchAll(/(?:https?:\/\/|mailto:)([^\s,;<>]+)/gi)) {
    const candidate = match[0]!;
    try {
      const url = new URL(candidate);
      if (url.protocol === "mailto:") {
        const address = decodeURIComponent(url.pathname);
        const domain = address.split("@")[1];
        if (domain) found.add(normalizeDomainName(domain));
      } else if (url.hostname) {
        found.add(normalizeDomainName(url.hostname));
      }
    } catch {
      // Ignore malformed header targets; the unsubscribe workflow validates them separately.
    }
  }
  return [...found];
}

function actualLinkDomain(link: LinkInfo): string | null {
  try { return normalizeDomainName(new URL(link.normalizedUrl || link.rawUrl).hostname); }
  catch { return null; }
}

function displayedUrlDomain(link: LinkInfo): string | null {
  if (!link.visibleText || !/^(?:https?:\/\/|www\.)/i.test(link.visibleText.trim())) return null;
  const value = /^www\./i.test(link.visibleText.trim())
    ? `https://${link.visibleText.trim()}`
    : link.visibleText.trim();
  try { return normalizeDomainName(new URL(value).hostname); }
  catch { return null; }
}

/** Domains asserted by independent message metadata. */
export function messageIdentityCandidateDomains(envelope: CanonicalEnvelope): string[] {
  const found = new Set<string>();
  if (envelope.replyTo?.domain) found.add(normalizeDomainName(envelope.replyTo.domain));
  for (const domain of domainsInText(envelope.listHeaders.listId)) found.add(domain);
  for (const domain of domainsFromUnsubscribe(envelope.listHeaders.listUnsubscribe)) found.add(domain);
  for (const link of envelope.links) {
    const actual = actualLinkDomain(link);
    const displayed = displayedUrlDomain(link);
    if (actual) found.add(actual);
    if (displayed) found.add(displayed);
  }
  return [...found].filter((domain) => domain && !isKnownSenderRelay(domain));
}

export function relayLocalPartEncodesDomain(address: string, domain: string): boolean {
  const localPart = address.split("@")[0]?.toLowerCase() ?? "";
  const encoded = organizationalDomain(domain).replace(/\./g, "_");
  if (!localPart || !encoded) return false;
  return localPart.includes(`_at_${encoded}_`)
    || localPart.endsWith(`_at_${encoded}`)
    || localPart.includes(`_${encoded}_`)
    || localPart.endsWith(`_${encoded}`);
}

/**
 * Apple relay aliases commonly encode the original destination as underscore-
 * separated labels after `_at_`, followed by a random token. Generate all
 * plausible suffix domains before the first random-looking token; the normal
 * organizational-domain function collapses prefixes such as `notice_` or
 * `info_`. This is format-based and works for domains never seen by the app.
 */
export function relayAliasDomainCandidates(address: string): string[] {
  const localPart = address.split("@")[0]?.toLowerCase() ?? "";
  const marker = localPart.lastIndexOf("_at_");
  if (marker < 0) return [];

  const tail = localPart.slice(marker + 4).split("_").filter(Boolean);
  const stable: string[] = [];
  for (const token of tail) {
    if (!/^[a-z-]{2,63}$/.test(token)) break;
    stable.push(token);
  }
  if (stable.length < 2) return [];

  const candidates = new Set<string>();
  for (let start = 0; start <= stable.length - 2; start++) {
    const candidate = stable.slice(start).join(".");
    const organization = organizationalDomain(candidate);
    if (organization && organization.includes(".")) candidates.add(organization);
  }
  return [...candidates];
}

export function verifiedRelayOriginDomains(envelope: CanonicalEnvelope): string[] {
  if (!envelope.from.address || !envelope.from.domain || !isKnownSenderRelay(envelope.from.domain)) return [];
  if (!authenticationPassed(envelope)) return [];

  const candidates = new Set([
    ...messageIdentityCandidateDomains(envelope),
    ...relayAliasDomainCandidates(envelope.from.address),
  ]);
  const origins = new Set<string>();
  for (const candidate of candidates) {
    if (isSharedMailboxDomain(candidate)) continue;
    const organization = organizationalDomain(candidate);
    if (organization && relayLocalPartEncodesDomain(envelope.from.address, organization)) origins.add(organization);
  }
  return [...origins];
}

/** Returns authenticated organizational domains for previously unseen senders. */
export function authenticatedSenderIdentityDomains(envelope: CanonicalEnvelope): string[] {
  if (!authenticationPassed(envelope) || !envelope.from.domain) return [];
  const fromDomain = normalizeDomainName(envelope.from.domain);

  if (isKnownSenderRelay(fromDomain)) return verifiedRelayOriginDomains(envelope);
  if (isSharedMailboxDomain(fromDomain)) return [];
  if (envelope.replyTo?.domain && !sameOrganizationalDomain(fromDomain, envelope.replyTo.domain)) return [];

  const organization = organizationalDomain(fromDomain);
  return organization ? [organization] : [];
}

export function hasAuthenticatedOrganizationalIdentity(envelope: CanonicalEnvelope): boolean {
  return authenticatedSenderIdentityDomains(envelope).length > 0;
}

/** Deprecated compatibility aliases: identity is structural, not brand-specific. */
export const hasDeterministicOfficialIdentity = hasAuthenticatedOrganizationalIdentity;
export const isDirectOfficialSenderDomain = (envelope: CanonicalEnvelope): boolean => {
  if (!envelope.from.domain || isKnownSenderRelay(envelope.from.domain)) return false;
  return hasAuthenticatedOrganizationalIdentity(envelope);
};
export const isOfficialPrivateRelaySender = (envelope: CanonicalEnvelope): boolean =>
  verifiedRelayOriginDomains(envelope).length > 0;
export const isOfficialBrandSender = hasAuthenticatedOrganizationalIdentity;

export function identityDomainMatches(envelope: CanonicalEnvelope, domain: string): boolean {
  const organization = organizationalDomain(domain);
  return Boolean(organization && authenticatedSenderIdentityDomains(envelope).includes(organization));
}

export function sensitiveActionText(text: string | null): boolean {
  return Boolean(text && /\b(?:sign[ -]?in|log[ -]?in|verify|confirm|unlock|reset password|change password|view document|review document|pay now|update payment|claim account|validate wallet)\b/i.test(text));
}
