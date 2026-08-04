import type { LayerResult } from "../verdict.js";

/**
 * Layer 5 — Destination classification (spec Section 5 + 8.5).
 *
 * CRITICAL: spec 8.1 ("Never run live deep-link visits automatically
 * during mailbox scanning") and 8.5 ("Explicit per-message action only in
 * Milestone 1; never automatic for every mailbox message") mean this layer
 * must NEVER run as part of the default Quick/Full/Spam scan pipeline.
 *
 * runDestinationClassification() is only ever called from the explicit
 * "Analyze Links" action handler (workflows/analyzeLinks.ts), never from
 * the scan pipeline. The scan pipeline instead calls
 * destinationLayerNotRun(), which returns "incomplete" so the verdict
 * engine correctly refuses to call the message "safe" purely because this
 * layer didn't run — it just means link destinations are Unknown, not
 * that they're clean.
 */
export function destinationLayerNotRun(): LayerResult {
  return {
    layer: "destination_classification",
    applicable: true,
    evidence: [],
    incomplete: true,
    incompleteReason: "Destination analysis only runs via the explicit Analyze Links action, not during scans.",
  };
}

export interface DestinationResult {
  url: string;
  classification:
    | "benign"
    | "credential_trap"
    | "adult_dating"
    | "fake_support"
    | "crypto_payment"
    | "malware"
    | "notification_trap"
    | "blocked_unsafe_target"
    | "error";
  hasForm: boolean;
  hasPasswordField: boolean;
  detail: string;
}

/**
 * Real implementation for the explicit Analyze Links action.
 * NOTE: this sandbox's egress is restricted to package registries and
 * cannot reach arbitrary mail-link destinations, so the actual fetch call
 * is isolated behind `fetchImpl` for dependency injection — in this build
 * it is exercised against fixture data only. On your machine, wire
 * `fetchImpl` to the hardened isolated resolver described below.
 *
 * Hardened resolver requirements (spec 8.5, Section 10):
 * - block localhost, private ranges (10/8, 172.16/12, 192.168/16, 127/8),
 *   link-local (169.254/16, fe80::/10), cloud metadata (169.254.169.254),
 *   and non-http(s) schemes
 * - resolve DNS once and pin the connection to that IP to prevent
 *   DNS-rebinding between the check and the actual fetch
 * - cap redirects (max 3), response size (e.g. 512KB), content types
 *   (text/html, text/plain only), and total time (e.g. 5s)
 * - never execute downloaded files, submit forms, or send mailbox
 *   cookies/session data
 */
export async function classifyDestination(
  url: string,
  fetchImpl: (u: string) => Promise<{ finalUrl: string; contentType: string; body: string } | null>
): Promise<DestinationResult> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { url, classification: "error", hasForm: false, hasPasswordField: false, detail: "Malformed URL." };
  }

  if (isBlockedTarget(parsed)) {
    return {
      url,
      classification: "blocked_unsafe_target",
      hasForm: false,
      hasPasswordField: false,
      detail: "Destination resolves to a private, loopback, link-local, or cloud-metadata address and was blocked before fetching.",
    };
  }

  const result = await fetchImpl(url);
  if (!result) {
    return { url, classification: "error", hasForm: false, hasPasswordField: false, detail: "Fetch failed, timed out, or exceeded limits." };
  }

  const hasForm = /<form[\s>]/i.test(result.body);
  const hasPasswordField = /<input[^>]+type=["']?password/i.test(result.body);
  const lower = result.body.toLowerCase();

  let classification: DestinationResult["classification"] = "benign";
  if (hasPasswordField) classification = "credential_trap";
  else if (/dating|adult|onlyfans|hookup/.test(lower)) classification = "adult_dating";
  else if (/wallet|seed phrase|connect wallet|metamask/.test(lower)) classification = "crypto_payment";
  else if (/support agent|call now|your computer is infected/.test(lower)) classification = "fake_support";
  else if (/enable notifications|allow notifications/.test(lower)) classification = "notification_trap";

  return { url, classification, hasForm, hasPasswordField, detail: `Classified from final destination ${result.finalUrl}.` };
}

function isBlockedTarget(url: URL): boolean {
  if (!["http:", "https:"].includes(url.protocol)) return true;
  const host = url.hostname;
  if (host === "localhost" || host === "0.0.0.0" || host === "169.254.169.254") return true;
  if (/^127\./.test(host)) return true;
  if (/^10\./.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return true;
  if (/^192\.168\./.test(host)) return true;
  if (/^169\.254\./.test(host)) return true;
  if (host === "::1" || host.startsWith("fe80:") || host.startsWith("fc") || host.startsWith("fd")) return true;
  return false;
}
