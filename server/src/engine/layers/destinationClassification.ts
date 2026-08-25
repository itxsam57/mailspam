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

const EICAR_TEST_SIGNATURE = "x5o!p%@ap[4\\pzx54(p^)7cc)7}$eicar-standard-antivirus-test-file!$h+h*";

/**
 * Conservative static destination-content inspection. This is intentionally
 * narrower than a browser antivirus/sandbox: fetched text is never executed.
 * "malware" is emitted only for the harmless EICAR AV test signature or a
 * deterministic download/decode/execute chain that is implausible in ordinary
 * storefront/login prose. Unknown content remains error/benign according to the
 * bounded fetch result rather than being overclaimed as malware.
 */
function containsDeterministicMalwareBehavior(body: string): boolean {
  const lower = body.toLowerCase();
  if (lower.includes(EICAR_TEST_SIGNATURE)) return true;

  const hasPowerShell = /(?:^|[^a-z0-9_])powershell(?:\.exe)?(?:[^a-z0-9_]|$)/i.test(lower);
  const hasEncodedExecution = /(?:-enc(?:odedcommand)?\b|frombase64string\s*\()/i.test(lower);
  const hasDownload = /(?:downloadstring\s*\(|downloadfile\s*\(|invoke-webrequest\b|start-bitstransfer\b|net\.webclient\b)/i.test(lower);
  const hasExecution = /(?:invoke-expression\b|\biex\s*(?:\(|\s)|start-process\b|cmd\.exe\b|cmd\s+\/c\b)/i.test(lower);
  if (hasPowerShell && hasEncodedExecution && hasDownload && hasExecution) return true;

  const hasLolbin = /(?:^|[^a-z0-9_])(?:mshta|regsvr32|rundll32)(?:\.exe)?(?:[^a-z0-9_]|$)/i.test(lower);
  const hasRemoteScript = /(?:https?:\/\/|javascript:|vbscript:|scrobj\.dll)/i.test(lower);
  if (hasLolbin && hasRemoteScript) return true;

  const unixDownloadExecute = /(?:^|[;&|\s])(?:curl|wget)(?:\s|$)[^\r\n]{0,2048}\|\s*(?:\/bin\/)?(?:ba|z|k)?sh(?:\s|$)/im.test(lower);
  return unixDownloadExecute;
}

function transportDetail(url: URL): string {
  return url.protocol === "http:"
    ? "Submitted destination uses unencrypted HTTP transport."
    : "Submitted destination uses HTTPS transport.";
}

/**
 * Explicit Analyze Links classifier. Network acquisition is isolated behind
 * fetchImpl and the production composition root supplies hardenedFetch, which
 * performs resolve/validate/socket-pin per redirect hop with strict time,
 * redirect, content-type and body limits. The classifier never executes
 * downloaded content, submits forms or runs during mailbox scans.
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
      detail: "Destination is a private, loopback, link-local, metadata, or non-HTTP(S) target and was blocked before fetching.",
    };
  }

  const transport = transportDetail(parsed);
  const result = await fetchImpl(url);
  if (!result) {
    return {
      url,
      classification: "error",
      hasForm: false,
      hasPasswordField: false,
      detail: `${transport} Fetch failed, timed out, was blocked by network safety checks, or exceeded inspection limits.`,
    };
  }

  if (result.contentType !== "text/html" && result.contentType !== "text/plain") {
    return {
      url,
      classification: "error",
      hasForm: false,
      hasPasswordField: false,
      detail: result.contentType
        ? `${transport} Destination returned unsupported content type ${result.contentType}; it was not treated as benign.`
        : `${transport} Destination did not provide an inspectable text content type; it was not treated as benign.`,
    };
  }

  const hasForm = /<form[\s>]/i.test(result.body);
  const hasPasswordField = /<input[^>]+type=["']?password/i.test(result.body);
  const lower = result.body.toLowerCase();

  let classification: DestinationResult["classification"] = "benign";
  if (containsDeterministicMalwareBehavior(result.body)) classification = "malware";
  else if (hasPasswordField) classification = "credential_trap";
  else if (/dating|adult|onlyfans|hookup/.test(lower)) classification = "adult_dating";
  else if (/wallet|seed phrase|connect wallet|metamask/.test(lower)) classification = "crypto_payment";
  else if (/support agent|call now|your computer is infected/.test(lower)) classification = "fake_support";
  else if (/enable notifications|allow notifications/.test(lower)) classification = "notification_trap";

  // Do not copy a complete destination (which may contain path/query secrets)
  // into coordinator caches or operational telemetry.
  return {
    url,
    classification,
    hasForm,
    hasPasswordField,
    detail: classification === "malware"
      ? `${transport} Fetched destination text matched a deterministic local malware-behavior signature. Content was inspected as text and never executed.`
      : classification === "benign"
        ? `${transport} No deterministic credential trap or malware behavior was found in the inspected destination text. This does not prove the destination is safe.`
        : `${transport} Classified from the resolved destination content as ${classification.replace(/_/g, " ")}.`,
  };
}

function isBlockedTarget(url: URL): boolean {
  if (!["http:", "https:"].includes(url.protocol)) return true;
  if (url.username || url.password) return true;
  const host = url.hostname.toLowerCase();
  if (host === "localhost" || host === "0.0.0.0" || host === "169.254.169.254") return true;
  if (/^127\./.test(host)) return true;
  if (/^10\./.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return true;
  if (/^192\.168\./.test(host)) return true;
  if (/^169\.254\./.test(host)) return true;
  if (host === "[::1]" || host === "::1" || host.startsWith("[fe80:") || host.startsWith("fe80:") || host.startsWith("[fc") || host.startsWith("fc") || host.startsWith("[fd") || host.startsWith("fd")) return true;
  return false;
}
