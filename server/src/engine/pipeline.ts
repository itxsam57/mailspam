import type { CanonicalEnvelope } from "../canonical/envelope.js";
import { computeVerdict, type LayerResult, type ScoredMessage, type Verdict } from "./verdict.js";
import {
  authenticationPassed,
  hasAuthenticatedOrganizationalIdentity,
} from "./identitySignals.js";
import { transportAuthLayer } from "./layers/transportAuth.js";
import { providerContextLayer } from "./layers/providerContext.js";
import { identityImpersonationLayer } from "./layers/identityImpersonation.js";
import { messageIntentLayer } from "./layers/messageIntent.js";
import { structuralConsistencyLayer } from "./layers/structuralConsistency.js";
import { linkStructureLayer } from "./layers/linkStructure.js";
import { destinationLayerNotRun } from "./layers/destinationClassification.js";
import { attachmentQrLayer } from "./layers/attachmentQr.js";
import { htmlInteractionLayer } from "./layers/htmlInteraction.js";
import { relationshipContextLayer } from "./layers/relationshipContext.js";
import { personalRulesLayer, type PersonalPolicyStore } from "./layers/personalRules.js";
import { globalIntelligenceLayer, type ThreatFeedCache } from "./layers/globalIntelligence.js";

export { authenticationPassed } from "./identitySignals.js";

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

function responsePolicy(verdict: Verdict): ResponseAction {
  switch (verdict) {
    case "safe": return "none";
    case "review": return "none";
    case "high_risk": return "allow_one_click_block";
    case "confirmed_threat": return "auto_trash_allowed";
    case "unknown": return "none";
  }
}

function isBoundedReadableContent(envelope: CanonicalEnvelope): boolean {
  if (envelope.diagnostics.contentCoverage === "bounded_sufficient") return true;
  if (envelope.parseStatus !== "partial" || envelope.parseNotes.length === 0) return false;
  return envelope.parseNotes.every((note) => /^Readable text was bounded to \d+ bytes\.$/.test(note));
}

function boundedContentAllowsSafe(envelope: CanonicalEnvelope): boolean {
  if (!isBoundedReadableContent(envelope) || !authenticationPassed(envelope)) return false;

  const visibleLength = `${envelope.textPreview ?? ""} ${envelope.htmlSignals?.extractedText ?? ""}`.trim().length;
  if (hasAuthenticatedOrganizationalIdentity(envelope)) return visibleLength >= 80;

  const listIdentity = Boolean(envelope.listHeaders.listId || envelope.listHeaders.listUnsubscribe);
  return listIdentity && visibleLength >= 160;
}

function adaptiveLegitimateAllowsSafe(
  envelope: CanonicalEnvelope,
  layerResults: LayerResult[],
  personalResult: LayerResult,
  globalResult: LayerResult,
): boolean {
  if (!authenticationPassed(envelope) || envelope.folder === "spam" || envelope.folder === "trash") return false;

  const learnedLegitimate = personalResult.evidence.some((item) => item.code === "TRUSTED_SENDER") ||
    globalResult.evidence.some((item) => item.code === "GLOBAL_LEGITIMATE_CONSENSUS");
  if (!learnedLegitimate) return false;

  const positiveRisk = layerResults.flatMap((layer) => layer.evidence)
    .filter((item) => item.scoreContribution > 0);
  const totalRisk = positiveRisk.reduce((sum, item) => sum + item.scoreContribution, 0);

  // Learning can remove repeated nuisance Review decisions only when every
  // remaining risk item is weak context. A single >=2 security contribution,
  // a community warning, provider Junk placement, auth failure, scam intent,
  // suspicious link/attachment, or High-Risk total remains authoritative.
  return totalRisk >= 2 && totalRisk <= 3 &&
    positiveRisk.length > 0 &&
    positiveRisk.every((item) => item.scoreContribution <= 1);
}

export function scanMessage(
  envelope: CanonicalEnvelope,
  deps: { personalPolicy: PersonalPolicyStore; threatFeed: ThreatFeedCache },
): ScanResult {
  const { result: personalResult, confirmedByPersonalBlock } = personalRulesLayer(envelope, deps.personalPolicy);
  const { result: globalResult, confirmedByGlobalRule } = globalIntelligenceLayer(envelope, deps.threatFeed);
  const identityResult = identityImpersonationLayer(envelope);
  const intentResult = messageIntentLayer(envelope);

  const layerResults = [
    providerContextLayer(envelope),
    transportAuthLayer(envelope),
    identityResult,
    intentResult,
    structuralConsistencyLayer(envelope, identityResult),
    linkStructureLayer(envelope),
    destinationLayerNotRun(),
    attachmentQrLayer(envelope),
    htmlInteractionLayer(envelope),
    relationshipContextLayer(envelope),
    personalResult,
    globalResult,
  ];
  const exactMessageApprovedByUser = personalResult.evidence.some(
    (item) => item.code === "APPROVED_MESSAGE_EXCEPTION",
  );

  const scored = computeVerdict({
    parseStatus: envelope.parseStatus,
    layerResults,
    confirmedByRule: confirmedByPersonalBlock || confirmedByGlobalRule,
    boundedContentAllowsSafe: boundedContentAllowsSafe(envelope),
    exactMessageApprovedByUser,
    adaptiveLegitimateAllowsSafe: adaptiveLegitimateAllowsSafe(envelope, layerResults, personalResult, globalResult),
  });

  return { envelope, scored, action: responsePolicy(scored.verdict) };
}
