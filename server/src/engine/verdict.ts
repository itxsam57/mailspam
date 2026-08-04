/**
 * Verdict model (spec Section 7).
 *
 * Hard rule: "No warning found in available metadata" must never be
 * presented as proof of safety when body/links/attachments were
 * unavailable. That is enforced structurally here: computeVerdict()
 * cannot return "safe" if envelope.parseStatus !== "complete" — it is
 * forced to "unknown".
 */

export type Verdict = "safe" | "review" | "high_risk" | "confirmed_threat" | "unknown";

export interface Evidence {
  layer: string; // e.g. "identity_impersonation"
  code: string; // stable machine-readable reason code
  description: string; // human-readable, shown in the "Explain" card
  scoreContribution: number;
  source: "local" | "cache" | "signed_feed" | "personal_rule";
}

export interface LayerResult {
  layer: string;
  applicable: boolean;
  evidence: Evidence[];
  /** True if this layer could not run to completion (e.g. destination fetch blocked/timed out, or content unavailable to parse). */
  incomplete: boolean;
  incompleteReason?: string;
  /**
   * Only set this true when `incomplete` reflects content that genuinely
   * couldn't be read/fetched (spec 7's "partial analysis" rule) — that's
   * what forces the verdict to "unknown" instead of "safe".
   *
   * Leave it false/undefined for layers deliberately not run by design at
   * this stage of the pipeline (e.g. destination classification during a
   * scan, per spec 8.1/8.5) — that's an intentional scope limitation, not
   * missing/unavailable content, so it must not make every scanned message
   * "Unknown" and defeat Quick/Full/Spam scan entirely.
   */
  blocksSafeVerdict?: boolean;
}

export interface ScoredMessage {
  score: number;
  evidence: Evidence[];
  verdict: Verdict;
  /** True if a personal block or signed global rule matched directly (confirmed_threat path). */
  confirmedByRule: boolean;
  layerResults: LayerResult[];
}

const HIGH_RISK_THRESHOLD = 6;
const REVIEW_THRESHOLD = 2;

export function computeVerdict(params: {
  parseStatus: "complete" | "partial" | "malformed" | "inaccessible" | "skipped";
  layerResults: LayerResult[];
  confirmedByRule: boolean;
}): ScoredMessage {
  const { parseStatus, layerResults, confirmedByRule } = params;

  const evidence = layerResults.flatMap((l) => l.evidence);
  const score = evidence.reduce((sum, e) => sum + e.scoreContribution, 0);
  const anyLayerIncomplete = layerResults.some((l) => l.incomplete && l.blocksSafeVerdict);

  // Confirmed threat (personal block or signed global rule) short-circuits everything.
  if (confirmedByRule) {
    return { score, evidence, verdict: "confirmed_threat", confirmedByRule: true, layerResults };
  }

  // Structural rule: content that wasn't fully parsed/fetched can NEVER be "safe",
  // even if zero evidence was found in what little was available.
  if (parseStatus !== "complete" || anyLayerIncomplete) {
    // Unless strong evidence already pushed it to high_risk despite partial data —
    // partial evidence of danger should still warn, just never clear to "safe".
    if (score >= HIGH_RISK_THRESHOLD) {
      return { score, evidence, verdict: "high_risk", confirmedByRule: false, layerResults };
    }
    return { score, evidence, verdict: "unknown", confirmedByRule: false, layerResults };
  }

  if (score >= HIGH_RISK_THRESHOLD) {
    return { score, evidence, verdict: "high_risk", confirmedByRule: false, layerResults };
  }
  if (score >= REVIEW_THRESHOLD) {
    return { score, evidence, verdict: "review", confirmedByRule: false, layerResults };
  }
  return { score, evidence, verdict: "safe", confirmedByRule: false, layerResults };
}
