import type { CanonicalEnvelope, LinkInfo } from "../../canonical/envelope.js";
import { organizationalDomain, sameOrganizationalDomain } from "../../util/domainRelation.js";
import { canonicalizeWebDestination } from "../../util/htmlInteraction.js";
import {
  authenticatedSenderIdentityDomains,
  sensitiveActionText,
} from "../identitySignals.js";
import type { LayerResult } from "../verdict.js";

/**
 * Layer 4 — Link structure.
 * Local URL parsing only: shortening services, punycode, raw IP hosts,
 * unusual ports, literal displayed-URL deception, HTML interaction provenance,
 * and sensitive action links that leave an authenticated sender's organization.
 * No brand list is used.
 */
const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
]);

const NON_NAVIGATING_SCHEMES = new Set(["cid:", "mailto:", "sms:", "tel:"]);
const UNSAFE_SCHEMES = new Set(["data:", "file:", "javascript:", "vbscript:"]);
const URL_ACTION_WORDS = new Set([
  "account", "auth", "authenticate", "authentication", "credential", "credentials",
  "login", "password", "recover", "recovery", "reset", "secure", "security",
  "signin", "verify", "verification",
]);
const GENERIC_SUBDOMAIN_WORDS = new Set([
  "app", "apps", "auth", "authenticate", "authentication", "account", "accounts",
  "client", "cloud", "credential", "credentials", "id", "identity", "login", "mail",
  "mobile", "online", "portal", "secure", "security", "service", "services", "signin",
  "support", "user", "users", "verify", "verification", "web", "www",
]);

function isRawIp(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || (/^[0-9a-f:]+$/i.test(host) && host.includes(":"));
}

function isPunycode(host: string): boolean {
  return host.split(".").some((label) => label.startsWith("xn--"));
}

function addUniqueEvidence(
  evidence: LayerResult["evidence"],
  seen: Set<string>,
  key: string,
  item: LayerResult["evidence"][number],
) {
  if (seen.has(key)) return;
  seen.add(key);
  evidence.push(item);
}

function displayedUrl(text: string | null): URL | null {
  if (!text) return null;
  const trimmed = text.trim();
  if (!/^(?:https?:\/\/|www\.)/i.test(trimmed)) return null;
  try { return new URL(/^www\./i.test(trimmed) ? `https://${trimmed}` : trimmed); }
  catch { return null; }
}

function normalizedLinkValue(link: LinkInfo): string {
  return canonicalizeWebDestination((link.normalizedUrl || link.rawUrl).trim(), null);
}

function explicitScheme(value: string): string | null {
  return value.match(/^([a-z][a-z0-9+.-]*:)/i)?.[1]?.toLowerCase() ?? null;
}

function isNonNavigatingReference(link: LinkInfo): boolean {
  const values = [link.rawUrl.trim(), normalizedLinkValue(link)];
  return values.some((value) => !value || value.startsWith("#"))
    || values.some((value) => {
      const scheme = explicitScheme(value);
      return scheme !== null && NON_NAVIGATING_SCHEMES.has(scheme);
    });
}

function decodedWords(value: string): string[] {
  let decoded = value;
  try { decoded = decodeURIComponent(value); }
  catch { /* Keep malformed encodings as literal bounded structure. */ }
  return decoded
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

/**
 * Detect identity-like labels combined with sign-in/verification wording on a
 * subdomain that is not owned by that identity label. This is deliberately
 * generic: no organization or brand allowlist is compiled into the engine.
 * A normal `brand-login.brand.example` shape is not flagged because the
 * distinctive token matches the registrable organization's own label.
 */
function identityActionSubdomain(host: string): string | null {
  const organization = organizationalDomain(host);
  if (!organization || organization === host || !host.endsWith(`.${organization}`)) return null;
  const organizationLabel = organization.split(".")[0]?.toLowerCase() ?? "";
  const prefix = host.slice(0, -(organization.length + 1));
  for (const label of prefix.split(".")) {
    const words = decodedWords(label);
    if (!words.some((word) => URL_ACTION_WORDS.has(word))) continue;
    const distinctive = words.find((word) => (
      word.length >= 4
      && !URL_ACTION_WORDS.has(word)
      && !GENERIC_SUBDOMAIN_WORDS.has(word)
      && word !== organizationLabel
    ));
    if (distinctive) return label;
  }
  return null;
}

function hasSensitiveAccountPath(url: URL): boolean {
  const words = new Set(decodedWords(url.pathname));
  let matched = 0;
  for (const word of words) {
    if (URL_ACTION_WORDS.has(word)) matched += 1;
    if (matched >= 2) return true;
  }
  return false;
}

function isAuthenticatedBulkRedirect(
  envelope: CanonicalEnvelope,
  senderIdentities: string[],
  link: LinkInfo,
  displayed: URL,
  actual: URL,
): boolean {
  const hasBulkMailMetadata = Boolean(
    envelope.listHeaders.listId ||
    envelope.listHeaders.listUnsubscribe ||
    envelope.listHeaders.listUnsubscribePost,
  );
  if (!hasBulkMailMetadata || senderIdentities.length === 0) return false;
  if (!senderIdentities.some((identity) => sameOrganizationalDomain(identity, displayed.hostname))) return false;
  if (sensitiveActionText(link.visibleText)) return false;
  if (actual.protocol !== "https:") return false;
  if (isRawIp(actual.hostname) || isPunycode(actual.hostname)) return false;
  return !actual.port || actual.port === "443";
}

export function linkStructureLayer(envelope: CanonicalEnvelope): LayerResult {
  const evidence: LayerResult["evidence"] = [];
  const seen = new Set<string>();
  const senderIdentities = authenticatedSenderIdentityDomains(envelope);
  let actionMismatchRecorded = false;

  for (const link of envelope.links) {
    if (isNonNavigatingReference(link)) continue;

    const value = normalizedLinkValue(link);
    const scheme = explicitScheme(value);
    if (scheme && UNSAFE_SCHEMES.has(scheme)) {
      addUniqueEvidence(evidence, seen, `UNSAFE_LINK_SCHEME:${scheme}`, {
        layer: "link_structure",
        code: "UNSAFE_LINK_SCHEME",
        description: `Link uses unsafe scheme "${scheme.slice(0, -1)}" instead of a normal web destination.`,
        scoreContribution: 4,
        source: "local",
      });
      continue;
    }

    let url: URL;
    try { url = new URL(value); }
    catch {
      addUniqueEvidence(evidence, seen, `MALFORMED_URL:${value.toLowerCase()}`, {
        layer: "link_structure",
        code: "MALFORMED_URL",
        description: `Link "${link.rawUrl}" could not be parsed as a valid URL.`,
        scoreContribution: 1,
        source: "local",
      });
      continue;
    }

    // Mail, phone, content-id and fragment references were filtered above.
    // Other non-web schemes remain visible as low-weight evidence rather than
    // being mislabeled as malformed URLs or silently ignored.
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      addUniqueEvidence(evidence, seen, `NON_WEB_LINK_SCHEME:${url.protocol}`, {
        layer: "link_structure",
        code: "NON_WEB_LINK_SCHEME",
        description: `Link uses non-web scheme "${url.protocol.slice(0, -1)}".`,
        scoreContribution: 1,
        source: "local",
      });
      continue;
    }

    const host = url.hostname.toLowerCase();
    const linkIsSensitive = link.interaction === "form_action"
      || link.interaction === "automatic_redirect"
      || sensitiveActionText(link.visibleText);

    if (url.protocol === "http:") {
      addUniqueEvidence(evidence, seen, `INSECURE_HTTP_LINK:${host}`, {
        layer: "link_structure",
        code: "INSECURE_HTTP_LINK",
        description: "Link uses unencrypted HTTP transport instead of HTTPS, so traffic to the destination is not protected in transit.",
        scoreContribution: 1,
        source: "local",
      });
    }

    const identityActionLabel = identityActionSubdomain(host);
    if (identityActionLabel) {
      addUniqueEvidence(evidence, seen, `IDENTITY_ACTION_SUBDOMAIN:${organizationalDomain(host)}:${identityActionLabel}`, {
        layer: "link_structure",
        code: "IDENTITY_ACTION_SUBDOMAIN",
        description: "A destination subdomain combines an identity-like label with sign-in or verification wording outside that identity's registrable domain.",
        scoreContribution: 1,
        source: "local",
      });
    }

    if (hasSensitiveAccountPath(url)) {
      addUniqueEvidence(evidence, seen, `SENSITIVE_ACCOUNT_PATH:${host}`, {
        layer: "link_structure",
        code: "SENSITIVE_ACCOUNT_PATH",
        description: "The destination path combines multiple account, credential, sign-in, recovery, or verification action terms.",
        scoreContribution: 1,
        source: "local",
      });
    }

    if (link.interaction === "automatic_redirect") {
      addUniqueEvidence(evidence, seen, `AUTOMATIC_HTML_REDIRECT:${host}`, {
        layer: "link_structure",
        code: "AUTOMATIC_HTML_REDIRECT",
        description: `HTML requests an automatic redirect to "${host}" without a normal user-selected link.`,
        scoreContribution: 1,
        source: "local",
      });
    }

    if (SHORTENERS.has(host) && (senderIdentities.length === 0 || linkIsSensitive)) {
      addUniqueEvidence(evidence, seen, `URL_SHORTENER:${host}`, {
        layer: "link_structure",
        code: "URL_SHORTENER",
        description: `Link uses shortening service "${host}", which hides the real destination.`,
        scoreContribution: 1,
        source: "local",
      });
    }
    if (isRawIp(host)) {
      addUniqueEvidence(evidence, seen, `RAW_IP_HOST:${host}`, {
        layer: "link_structure",
        code: "RAW_IP_HOST",
        description: `Link points directly to a raw IP address (${host}) instead of a domain.`,
        scoreContribution: 3,
        source: "local",
      });
    }
    if (isPunycode(host)) {
      addUniqueEvidence(evidence, seen, `PUNYCODE_HOST:${host}`, {
        layer: "link_structure",
        code: "PUNYCODE_HOST",
        description: `Link host "${host}" uses punycode encoding, which can conceal a lookalike domain.`,
        scoreContribution: 3,
        source: "local",
      });
    }
    if (url.port && !["80", "443", ""].includes(url.port)) {
      addUniqueEvidence(evidence, seen, `UNUSUAL_PORT:${url.port}`, {
        layer: "link_structure",
        code: "UNUSUAL_PORT",
        description: `Link uses an unusual port (${url.port}).`,
        scoreContribution: 1,
        source: "local",
      });
    }

    const displayed = displayedUrl(link.visibleText);
    const authenticatedBulkRedirect = displayed
      ? isAuthenticatedBulkRedirect(envelope, senderIdentities, link, displayed, url)
      : false;
    if (displayed && !sameOrganizationalDomain(displayed.hostname, host) && !authenticatedBulkRedirect) {
      addUniqueEvidence(
        evidence,
        seen,
        `DISPLAYED_VS_ACTUAL_MISMATCH:${organizationalDomain(displayed.hostname)}:${organizationalDomain(host)}`,
        {
          layer: "link_structure",
          code: "DISPLAYED_VS_ACTUAL_MISMATCH",
          description: `Displayed link domain "${displayed.hostname}" does not match the actual destination "${host}".`,
          scoreContribution: 4,
          source: "local",
        },
      );
    }

    if (!actionMismatchRecorded && senderIdentities.length && linkIsSensitive) {
      const destinationOrganization = organizationalDomain(host);
      const aligned = senderIdentities.some((identity) => sameOrganizationalDomain(identity, destinationOrganization));
      if (!aligned) {
        actionMismatchRecorded = true;
        evidence.push({
          layer: "link_structure",
          code: "SENSITIVE_ACTION_CROSS_DOMAIN",
          description: `A sensitive action link leaves the authenticated sender organization and points to "${destinationOrganization}".`,
          scoreContribution: 2,
          source: "local",
        });
      }
    }
  }

  return { layer: "link_structure", applicable: envelope.links.length > 0, evidence, incomplete: false };
}
