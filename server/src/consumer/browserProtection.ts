import type { DestinationAnalysisCoordinator } from "../workflows/analyzeLinks.js";
import { evaluateConsumerScamCheck, type ConsumerScamCheckDependencies } from "./scamCheck.js";

export type BrowserProtectionDisposition = "allow" | "warn" | "block" | "unknown";

export interface BrowserUrlVerdictV1 {
  schemaVersion: 1;
  disposition: BrowserProtectionDisposition;
  url: string;
  reasonCodes: string[];
  explanation: string;
  destinationClassification: string | null;
  privacy: "single_explicit_or_navigation_url_no_history";
}

export interface BrowserProtectionRequestV1 {
  schemaVersion: 1;
  url: string;
  context: "navigation" | "download" | "explicit_check";
  download?: {
    filename?: string;
    mimeType?: string;
  };
}

export function assertBrowserProtectionRequest(input: unknown): asserts input is BrowserProtectionRequestV1 {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Browser protection request is invalid.");
  const value = input as Record<string, unknown>;
  if (Object.keys(value).some((key) => !["schemaVersion", "url", "context", "download"].includes(key)) || value.schemaVersion !== 1) {
    throw new Error("Browser protection request is invalid.");
  }
  if (typeof value.url !== "string" || value.url.length < 1 || value.url.length > 8_192) throw new Error("Browser URL is invalid.");
  const context = value.context;
  if (context !== "navigation" && context !== "download" && context !== "explicit_check") throw new Error("Browser protection context is invalid.");
  const parsed = new URL(value.url);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new Error("Browser protection accepts only HTTP(S) destinations.");
  if (value.download !== undefined) {
    if (!value.download || typeof value.download !== "object" || Array.isArray(value.download)) throw new Error("Download context is invalid.");
    const download = value.download as Record<string, unknown>;
    if (Object.keys(download).some((key) => key !== "filename" && key !== "mimeType")) throw new Error("Download context is invalid.");
    for (const field of [download.filename, download.mimeType]) {
      if (field !== undefined && (typeof field !== "string" || field.length > 1_024)) throw new Error("Download context is invalid.");
    }
  }
}

function downloadRisk(download: BrowserProtectionRequestV1["download"]): string[] {
  if (!download) return [];
  const filename = download.filename?.toLowerCase() ?? "";
  const mime = download.mimeType?.toLowerCase() ?? "";
  const reasons: string[] = [];
  if (/\.(?:exe|msi|scr|bat|cmd|ps1|js|jse|vbs|vbe|wsf|hta|lnk|iso|img|apk)$/i.test(filename)) reasons.push("EXECUTABLE_OR_SCRIPT_DOWNLOAD");
  if (/\.(?:docm|xlsm|pptm|xlam)$/i.test(filename)) reasons.push("MACRO_CAPABLE_DOCUMENT_DOWNLOAD");
  if (/application\/(?:x-msdownload|x-dosexec|x-sh|x-powershell)/i.test(mime)) reasons.push("EXECUTABLE_MIME_DOWNLOAD");
  return reasons;
}

export async function evaluateBrowserUrl(
  input: unknown,
  dependencies: {
    destinationAnalyzer: DestinationAnalysisCoordinator;
    scamCheck?: ConsumerScamCheckDependencies;
  },
): Promise<BrowserUrlVerdictV1> {
  assertBrowserProtectionRequest(input);
  const parsed = new URL(input.url);
  const normalizedUrl = parsed.toString();
  const intelligenceEntries = dependencies.scamCheck?.intelligenceEntries;
  // [] means a signed feed was successfully verified and currently contains no
  // matching entries. null/undefined means trusted Global Shield intelligence
  // is unavailable and Browser Protection must not silently treat that as safe.
  const intelligenceAvailable = Array.isArray(intelligenceEntries);
  const scam = evaluateConsumerScamCheck({ schemaVersion: 1, kind: "url", url: normalizedUrl }, dependencies.scamCheck ?? {});
  const envelope = {
    provider: "imap" as const,
    accountProof: "browser:ephemeral",
    messageId: "browser:ephemeral",
    providerNativeId: "browser:ephemeral",
    folder: "other" as const,
    providerFolderName: "browser",
    from: { displayName: null, address: null, domain: null },
    replyTo: null,
    subject: "",
    date: new Date(0).toISOString(),
    authentication: { spf: "unknown" as const, dkim: "unknown" as const, dmarc: "unknown" as const, arc: "unknown" as const },
    textPreview: null,
    htmlSignals: null,
    links: [{
      visibleText: normalizedUrl,
      rawUrl: normalizedUrl,
      normalizedUrl,
      claimedBrand: null,
      brandDomainMismatch: null,
      source: "body" as const,
      interaction: "navigation" as const,
    }],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete" as const,
    parseNotes: [],
    diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: normalizedUrl.length, encoding: "plain" as const, contentCoverage: "complete" as const },
  };
  const destination = await dependencies.destinationAnalyzer.analyze(envelope);
  const destinationResult = destination.results[0] ?? null;
  const positiveScamEvidence = scam.evidence.filter((item) => item.scoreContribution > 0);
  const downloadReasons = downloadRisk(input.download);
  const reasonCodes = [
    ...positiveScamEvidence.map((item) => item.code),
    ...downloadReasons,
    ...(!intelligenceAvailable ? ["GLOBAL_INTELLIGENCE_UNAVAILABLE"] : []),
  ];
  if (destinationResult?.classification && destinationResult.classification !== "benign") {
    reasonCodes.push(`DESTINATION_${destinationResult.classification.toUpperCase()}`);
  }

  const classification = destinationResult?.classification ?? null;
  const hardDestination = classification === "credential_trap" || classification === "malware";
  const cautionDestination = classification === "adult_dating"
    || classification === "fake_support"
    || classification === "crypto_payment"
    || classification === "notification_trap";
  const unverifiableDestination = classification === "error" || classification === "blocked_unsafe_target" || classification === null;
  const hasDownloadRisk = downloadReasons.length > 0;
  const hasPositiveScamEvidence = positiveScamEvidence.length > 0;

  // Browser Protection has two different evidence boundaries:
  // 1) mailbox provenance is intentionally absent for a URL-only check, which
  //    may make Scam Check's whole-message verdict Unknown; and
  // 2) signed Global Shield availability, which is independently knowable.
  // A benign destination with a verified feed and no positive URL evidence may
  // therefore be allowed. Missing signed intelligence remains fail-closed.
  const disposition: BrowserProtectionDisposition = hardDestination || scam.verdict === "confirmed_threat"
    ? "block"
    : scam.verdict === "high_risk" || scam.verdict === "review" || cautionDestination || hasDownloadRisk || hasPositiveScamEvidence
      ? "warn"
      : unverifiableDestination || !intelligenceAvailable
        ? "unknown"
        : "allow";

  return {
    schemaVersion: 1,
    disposition,
    url: normalizedUrl,
    reasonCodes: [...new Set(reasonCodes)].slice(0, 20),
    explanation: disposition === "block"
      ? "Email Shield found a hard local/signed or destination-level threat signal. Do not continue to this destination."
      : disposition === "warn"
        ? "Email Shield found suspicious URL, destination, or download evidence. Verify the destination independently before continuing."
        : disposition === "unknown"
          ? !intelligenceAvailable
            ? "Email Shield could not verify the current signed Global Shield intelligence feed, so this destination was not treated as safe."
            : "Email Shield could not obtain enough trustworthy destination evidence. The destination was not treated as safe."
          : "No strong deterministic threat signal was observed in the inspected destination or the verified Global Shield feed at check time. This is not a guarantee that future content cannot change.",
    destinationClassification: classification,
    privacy: "single_explicit_or_navigation_url_no_history",
  };
}
