import { isIP } from "node:net";
import { getDomain } from "tldts";

const REGISTRABLE_DOMAIN_OPTIONS = Object.freeze({
  allowPrivateDomains: true,
  extractHostname: false,
});

export function normalizeDomainName(domain: string): string {
  return domain.trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
}

/**
 * Return the registrable-domain boundary (public suffix + one registrant label).
 *
 * Security comparisons must not infer this boundary from a fixed number of
 * labels. Registry policy differs by suffix and the Public Suffix List also
 * contains wildcard, exception and privately operated tenant boundaries. The
 * bundled tldts snapshot gives this local/offline helper one shared source of
 * truth without DNS or network access at scan time.
 *
 * Unknown but syntactically parseable suffixes retain tldts' conservative
 * last-label behavior so fixture/test domains such as `example.test-domain`
 * continue to group their own subdomains. A bare known public suffix has no
 * registrable owner and therefore returns an empty identity boundary.
 */
export function organizationalDomain(domain: string): string {
  const normalized = normalizeDomainName(domain);
  if (!normalized || isIP(normalized)) return normalized;
  if (!normalized.includes(".")) return normalized;

  const registrable = getDomain(normalized, REGISTRABLE_DOMAIN_OPTIONS);
  return registrable ? normalizeDomainName(registrable) : "";
}

export function sameOrganizationalDomain(first: string, second: string): boolean {
  const a = organizationalDomain(first);
  const b = organizationalDomain(second);
  return Boolean(a && b && a === b);
}

export function isKnownSenderRelay(domain: string): boolean {
  const normalized = normalizeDomainName(domain);
  return normalized === "privaterelay.appleid.com" || normalized.endsWith(".privaterelay.appleid.com");
}
