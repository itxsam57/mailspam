/**
 * Verdict model (spec Section 7).
 *
 * Unavailable or incomplete content is never machine-labelled Safe. An exact
 * account-scoped approval may resolve ordinary fully-inspected Review evidence,
 * but it cannot override incomplete coverage, High Risk evidence, personal
 * blocks, or verified confirmed-threat rules.
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
  /**
   * Explicit approval of this exact message, never a sender/domain allowlist.
   * It may resolve ordinary fully-inspected Review evidence but never
   * unavailable content, High Risk, or Confirmed Threat.
   */
  exactMessageApprovedByUser?: boolean;
  /**
   * Authenticated campaign/sender learning may suppress only a borderline
   * Review made entirely from weak context. The pipeline computes this guard;
   * this function still refuses High Risk, confirmed, or unavailable content.
   */
  adaptiveLegitimateAllowsSafe?: boolean;
}): ScoredMessage {
  const {
    parseStatus,
    layerResults,
    confirmedByRule,
    boundedContentAllowsSafe = false,
    exactMessageApprovedByUser = false,
    adaptiveLegitimateAllowsSafe = false,
  } = params;

  const evidence = layerResults.flatMap((layer) => layer.evidence);
  // Risk evidence is monotonic. Personal trust is useful context, but it must
  // never cancel independent transport, intent, link, or attachment evidence.
  const score = evidence.reduce((sum, item) => sum + Math.max(0, item.scoreContribution), 0);
  const parseBlocksSafe = parseStatus !== "complete" && !boundedContentAllowsSafe;
  const hasUnavailableContent =
    parseBlocksSafe ||
    layerResults.some((layer) => layer.incomplete && layer.blocksSafeVerdict);

  // Hard/strong security decisions are authoritative. A prior user decision
  // about this exact message must never turn a newly High-Risk or confirmed
  // message into Safe after stronger evidence becomes available.
  if (confirmedByRule) {
    return { score, evidence, verdict: "confirmed_threat", confirmedByRule: true, layerResults };
  }
  if (score >= HIGH_RISK_THRESHOLD) {
    return { score, evidence, verdict: "high_risk", confirmedByRule: false, layerResults };
  }
  if (exactMessageApprovedByUser && !hasUnavailableContent) {
    return { score, evidence, verdict: "safe", confirmedByRule: false, layerResults };
  }
  if (adaptiveLegitimateAllowsSafe && !hasUnavailableContent) {
    return { score, evidence, verdict: "safe", confirmedByRule: false, layerResults };
  }
  if (score >= REVIEW_THRESHOLD) {
    return { score, evidence, verdict: "review", confirmedByRule: false, layerResults };
  }
  if (hasUnavailableContent) {
    return { score, evidence, verdict: "unknown", confirmedByRule: false, layerResults };
  }
  return { score, evidence, verdict: "safe", confirmedByRule: false, layerResults };
}
