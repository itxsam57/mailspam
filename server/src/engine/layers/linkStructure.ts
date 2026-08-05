import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import { hasDeterministicOfficialIdentity } from "./identityImpersonation.js";
import type { LayerResult } from "../verdict.js";

/**
 * Layer 4 — Link structure (spec Section 5).
 * Local URL parsing only: shortening services, punycode, raw IP hosts,
 * unusual ports, and text/href brand mismatch. This layer never fetches
 * anything over the network — that's Layer 5 (destination classification),
 * which spec 8.5 requires to be an explicit per-message action only.
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

export function linkStructureLayer(envelope: CanonicalEnvelope): LayerResult {
  const evidence: LayerResult["evidence"] = [];
  const seen = new Set<string>();
  const officialSender = hasDeterministicOfficialIdentity(envelope);
  let brandMismatchRecorded = false;

  for (const link of envelope.links) {
    let url: URL;
    try {
      url = new URL(link.normalizedUrl);
    } catch {
      addUniqueEvidence(evidence, seen, `MALFORMED_URL:${link.rawUrl}`, {
        layer: "link_structure",
        code: "MALFORMED_URL",
        description: `Link "${link.rawUrl}" could not be parsed as a valid URL.`,
        scoreContribution: 1,
        source: "local",
      });
      continue;
    }

    if (SHORTENERS.has(url.hostname)) {
      addUniqueEvidence(evidence, seen, `URL_SHORTENER:${url.hostname}`, {
        layer: "link_structure",
        code: "URL_SHORTENER",
        description: `Link uses shortening service "${url.hostname}", which hides the real destination.`,
        scoreContribution: 1,
        source: "local",
      });
    }

    if (isRawIp(url.hostname)) {
      addUniqueEvidence(evidence, seen, `RAW_IP_HOST:${url.hostname}`, {
        layer: "link_structure",
        code: "RAW_IP_HOST",
        description: `Link points directly to a raw IP address (${url.hostname}) instead of a domain.`,
        scoreContribution: 3,
        source: "local",
      });
    }

    if (isPunycode(url.hostname)) {
      addUniqueEvidence(evidence, seen, `PUNYCODE_HOST:${url.hostname}`, {
        layer: "link_structure",
        code: "PUNYCODE_HOST",
        description: `Link host "${url.hostname}" uses punycode encoding, often used to spoof lookalike domains.`,
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

    // A newsletter may contain many tracked footer, app-store, and social links.
    // Repeating the same structural ambiguity must never multiply a message's
    // risk score. For an authenticated deterministic official sender, a single
    // brand-link ambiguity is retained as a low-weight diagnostic; stronger
    // evidence such as raw IPs or displayed-URL deception still scores fully.
    if (link.claimedBrand && link.brandDomainMismatch && !brandMismatchRecorded) {
      brandMismatchRecorded = true;
      evidence.push({
        layer: "link_structure",
        code: "LINK_BRAND_MISMATCH",
        description: officialSender
          ? `An official sender used a tracked or indirect link whose destination does not directly match the visible "${link.claimedBrand}" label.`
          : `Link text implies "${link.claimedBrand}" but the destination domain doesn't match.`,
        scoreContribution: officialSender ? 1 : 4,
        source: "local",
      });
    }

    if (link.visibleText && /^https?:\/\//i.test(link.visibleText)) {
      try {
        const displayedUrl = new URL(link.visibleText);
        if (displayedUrl.hostname !== url.hostname) {
          addUniqueEvidence(
            evidence,
            seen,
            `DISPLAYED_VS_ACTUAL_MISMATCH:${displayedUrl.hostname}:${url.hostname}`,
            {
              layer: "link_structure",
              code: "DISPLAYED_VS_ACTUAL_MISMATCH",
              description: `Displayed link text ("${displayedUrl.hostname}") does not match the actual destination ("${url.hostname}").`,
              scoreContribution: 4,
              source: "local",
            },
          );
        }
      } catch {
        // visible text wasn't a real URL — nothing to compare
      }
    }
  }

  return { layer: "link_structure", applicable: envelope.links.length > 0, evidence, incomplete: false };
}
