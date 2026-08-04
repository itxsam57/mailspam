import type { CanonicalEnvelope } from "../canonical/envelope.js";
import { computeVerdict, type ScoredMessage, type Verdict } from "./verdict.js";
import { transportAuthLayer } from "./layers/transportAuth.js";
import { identityImpersonationLayer } from "./layers/identityImpersonation.js";
import { messageIntentLayer } from "./layers/messageIntent.js";
import { linkStructureLayer } from "./layers/linkStructure.js";
import { destinationLayerNotRun } from "./layers/destinationClassification.js";
import { attachmentQrLayer } from "./layers/attachmentQr.js";
import { relationshipContextLayer } from "./layers/relationshipContext.js";
import { personalRulesLayer, type PersonalPolicyStore } from "./layers/personalRules.js";
import { globalIntelligenceLayer, type ThreatFeedCache } from "./layers/globalIntelligence.js";

export type ResponseAction =
  | "none"
  | "warn"
  | "suggest_quarantine"
  | "allow_one_click_block"
  | "auto_trash_allowed";

export interface ScanResult {
  envelope: CanonicalEnvelope;
  scored: ScoredMessage;
  action: ResponseAction;
}

/**
 * Layer 11 — Response policy (spec Section 5, table "Verdict/Score/Action").
 * Deliberately separate from the detection score: policy decides what the
 * UI is ALLOWED to do automatically, never what it's forced to do.
 */
function responsePolicy(verdict: Verdict): ResponseAction {
  switch (verdict) {
    case "safe": return "none";
    case "review": return "none"; // no automatic Trash — user inspects
    case "high_risk": return "allow_one_click_block"; // warn + offer one-click action
    case "confirmed_threat": return "auto_trash_allowed"; // still gated by user's own policy setting
    case "unknown": return "none"; // show reason + retry path, never silently safe
  }
}

/**
 * Runs the full scan-time detection pipeline (Layers 1-4, 6-9) on a single
 * canonical envelope. Layer 5 (destination classification) is deliberately
 * NOT run here — it only runs from the explicit Analyze Links action
 * (spec 8.1, 8.5). Layer 10 (community reporting aggregation) is
 * Milestone 2 server-side scope and doesn't run per-message client-side.
 */
export function scanMessage(
  envelope: CanonicalEnvelope,
  deps: { personalPolicy: PersonalPolicyStore; threatFeed: ThreatFeedCache }
): ScanResult {
  const { result: personalResult, confirmedByPersonalBlock } = personalRulesLayer(envelope, deps.personalPolicy);
  const { result: globalResult, confirmedByGlobalRule } = globalIntelligenceLayer(envelope, deps.threatFeed);

  const layerResults = [
    transportAuthLayer(envelope),
    identityImpersonationLayer(envelope),
    messageIntentLayer(envelope),
    linkStructureLayer(envelope),
    destinationLayerNotRun(), // always "incomplete" at scan time — never fabricated as clean
    attachmentQrLayer(envelope),
    relationshipContextLayer(envelope),
    personalResult,
    globalResult,
  ];

  const scored = computeVerdict({
    parseStatus: envelope.parseStatus,
    layerResults,
    confirmedByRule: confirmedByPersonalBlock || confirmedByGlobalRule,
  });

  return { envelope, scored, action: responsePolicy(scored.verdict) };
}
