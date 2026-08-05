import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import { organizationalDomain, sameOrganizationalDomain } from "../../util/domainRelation.js";
import {
  authenticatedSenderIdentityDomains,
  sensitiveActionText,
} from "../identitySignals.js";
import type { LayerResult } from "../verdict.js";

/**
 * Layer 4 — Link structure.
 * Local URL parsing only: shortening services, punycode, raw IP hosts,
 * unusual ports, literal displayed-URL deception, and sensitive action links
 * that leave an authenticated sender's organization. No brand list is used.
 */
const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
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

export function linkStructureLayer(envelope: CanonicalEnvelope): LayerResult {
  const evidence: LayerResult["evidence"] = [];
  const seen = new Set<string>();
  const senderIdentities = authenticatedSenderIdentityDomains(envelope);
  let actionMismatchRecorded = false;

  for (const link of envelope.links) {
    let url: URL;
    try { url = new URL(link.normalizedUrl); }
    catch {
      addUniqueEvidence(evidence, seen, `MALFORMED_URL:${link.rawUrl}`, {
        layer: "link_structure",
        code: "MALFORMED_URL",
        description: `Link "${link.rawUrl}" could not be parsed as a valid URL.`,
        scoreContribution: 1,
        source: "local",
      });
      continue;
    }

    const host = url.hostname.toLowerCase();
    if (SHORTENERS.has(host)) {
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
    if (displayed && !sameOrganizationalDomain(displayed.hostname, host)) {
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

    if (!actionMismatchRecorded && senderIdentities.length && sensitiveActionText(link.visibleText)) {
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
