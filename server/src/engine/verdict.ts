/**
 * Verdict model (spec Section 7).
 *
 * Hard rule: genuinely unavailable content must never be presented as proof
 * of safety. A provider may deliberately bound a very large readable part;
 * the pipeline may permit Safe only when that bounded content is sufficient,
 * authentication passed, and a deterministic bulk/official identity signal
 * is present.
 */

export type Verdict = "safe" | "review" | "high_risk" | "confirmed_threat" | "unknown";

export interface Evidence {
  layer: string;
  code: string;
  description: string;
  scoreContribution: number;
  source: "local" | "cache" | "signed_feed" | "personal_rule";
}

export interface LayerResult {
  layer: string;
  applicable: boolean;
  evidence: Evidence[];
  incomplete: boolean;
  incompleteReason?: string;
  blocksSafeVerdict?: boolean;
}

export interface ScoredMessage {
  score: number;
  evidence: Evidence[];
  verdict: Verdict;
  confirmedByRule: boolean;
  layerResults: LayerResult[];
}

const HIGH_RISK_THRESHOLD = 6;
const REVIEW_THRESHOLD = 2;

export function computeVerdict(params: {
  parseStatus: "complete" | "partial" | "malformed" | "inaccessible" | "skipped";
  layerResults: LayerResult[];
  confirmedByRule: boolean;
  /** True only for authenticated, deterministically identified bounded mail. */
  boundedContentAllowsSafe?: boolean;
}): ScoredMessage {
  const { parseStatus, layerResults, confirmedByRule, boundedContentAllowsSafe = false } = params;

  const evidence = layerResults.flatMap((layer) => layer.evidence);
  const score = evidence.reduce((sum, item) => sum + item.scoreContribution, 0);
  const parseBlocksSafe = parseStatus !== "complete" && !boundedContentAllowsSafe;
  const hasUnavailableContent =
    parseBlocksSafe ||
    layerResults.some((layer) => layer.incomplete && layer.blocksSafeVerdict);

  if (confirmedByRule) {
    return { score, evidence, verdict: "confirmed_threat", confirmedByRule: true, layerResults };
  }
  if (score >= HIGH_RISK_THRESHOLD) {
    return { score, evidence, verdict: "high_risk", confirmedByRule: false, layerResults };
  }
  if (score >= REVIEW_THRESHOLD) {
    return { score, evidence, verdict: "review", confirmedByRule: false, layerResults };
  }
  if (hasUnavailableContent) {
    return { score, evidence, verdict: "unknown", confirmedByRule: false, layerResults };
  }
  return { score, evidence, verdict: "safe", confirmedByRule: false, layerResults };
}
