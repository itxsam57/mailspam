import type { CanonicalEnvelope } from "../canonical/envelope.js";
import { classifyDestination, type DestinationResult } from "../engine/layers/destinationClassification.js";

export interface AnalyzeLinksResult {
  results: DestinationResult[];
  /** Escalation: even if the scan-time verdict was "review", a credential trap here bumps the user-facing state. */
  escalatedToHighRisk: boolean;
}

/**
 * Wired to a single explicit user action ("Analyze Links" button on a
 * message card) — never called automatically during any scan (spec 8.1/8.5).
 * The production API composition root supplies hardenedFetch, which resolves
 * and validates DNS once per redirect hop and pins the outbound socket to a
 * validated public address before reading bounded text content.
 *
 * fetchImpl stays injectable so the deterministic classifier can be tested
 * without granting CI access to arbitrary mail-link destinations.
 */
export async function analyzeLinks(
  envelope: CanonicalEnvelope,
  fetchImpl: (u: string) => Promise<{ finalUrl: string; contentType: string; body: string } | null>
): Promise<AnalyzeLinksResult> {
  const results: DestinationResult[] = [];
  for (const link of envelope.links) {
    results.push(await classifyDestination(link.normalizedUrl, fetchImpl));
  }
  const escalatedToHighRisk = results.some(
    (r) => r.classification === "credential_trap" || r.classification === "malware"
  );
  return { results, escalatedToHighRisk };
}
