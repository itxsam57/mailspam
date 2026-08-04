import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import type { LayerResult } from "../verdict.js";

/**
 * Layer 2 — Identity and impersonation (spec Section 5).
 * Detects display-name abuse, reply-to mismatch, and brand/domain mismatch
 * using an official-domain registry + punycode normalization + string
 * distance — never a bare keyword match.
 */

// Minimal seed registry; production version should be data-driven and
// expanded to cover every brand named in spec Section 6.
export const OFFICIAL_BRAND_DOMAINS: Record<string, string[]> = {
  paypal: ["paypal.com"],
  apple: ["apple.com", "icloud.com"],
  google: ["google.com", "gmail.com"],
  microsoft: ["microsoft.com", "outlook.com", "live.com"],
  amazon: ["amazon.com"],
  "bank of america": ["bankofamerica.com"],
  chase: ["chase.com"],
  ups: ["ups.com"],
  fedex: ["fedex.com"],
  usps: ["usps.com"],
  docusign: ["docusign.net", "docusign.com"],
  "irs": ["irs.gov"],
};

function normalizeDomain(domain: string): string {
  // Punycode-aware lowering; full IDNA handled by adapter normalization upstream.
  return domain.trim().toLowerCase();
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

export function claimedBrandFromText(text: string): string | null {
  const lower = text.toLowerCase();
  for (const brand of Object.keys(OFFICIAL_BRAND_DOMAINS)) {
    // Word-boundary match only — naive substring matching false-positives on
    // e.g. "chase" inside "purchased". \b alone doesn't handle multi-word
    // brands cleanly, so use lookaround boundaries around the whole phrase.
    const escaped = brand.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp(`(?<![a-z0-9])${escaped}(?![a-z0-9])`, "i");
    if (re.test(lower)) return brand;
  }
  return null;
}

export function identityImpersonationLayer(envelope: CanonicalEnvelope): LayerResult {
  const evidence: LayerResult["evidence"] = [];

  const claimedBrand =
    claimedBrandFromText(envelope.from.displayName ?? "") ??
    claimedBrandFromText(envelope.subject);

  if (claimedBrand && envelope.from.domain) {
    const officialDomains = OFFICIAL_BRAND_DOMAINS[claimedBrand]!;
    const senderDomain = normalizeDomain(envelope.from.domain);
    const isOfficial = officialDomains.some((d) => senderDomain === d || senderDomain.endsWith(`.${d}`));

    if (!isOfficial) {
      const closest = Math.min(...officialDomains.map((d) => levenshtein(senderDomain, d)));
      const lookalike = closest > 0 && closest <= 3 && senderDomain.length > 3;

      evidence.push({
        layer: "identity_impersonation",
        code: lookalike ? "BRAND_LOOKALIKE_DOMAIN" : "BRAND_DOMAIN_MISMATCH",
        description: lookalike
          ? `Sender domain "${senderDomain}" closely resembles the official domain for "${claimedBrand}" but does not match it.`
          : `Message claims to be from "${claimedBrand}" but sender domain "${senderDomain}" is not an official domain for that brand.`,
        scoreContribution: lookalike ? 5 : 4,
        source: "local",
      });
    }
  }

  if (envelope.replyTo?.domain && envelope.from.domain) {
    const fromDomain = normalizeDomain(envelope.from.domain);
    const replyDomain = normalizeDomain(envelope.replyTo.domain);
    if (fromDomain !== replyDomain) {
      evidence.push({
        layer: "identity_impersonation",
        code: "REPLY_TO_MISMATCH",
        description: `Reply-To domain "${replyDomain}" differs from the From domain "${fromDomain}".`,
        scoreContribution: 2,
        source: "local",
      });
    }
  }

  return { layer: "identity_impersonation", applicable: true, evidence, incomplete: false };
}
