import type { CanonicalEnvelope } from "../canonical/envelope.js";
import { computeVerdict, type ScoredMessage, type Verdict } from "./verdict.js";
import { transportAuthLayer } from "./layers/transportAuth.js";
import { identityImpersonationLayer, isOfficialBrandSender } from "./layers/identityImpersonation.js";
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

function responsePolicy(verdict: Verdict): ResponseAction {
  switch (verdict) {
    case "safe": return "none";
    case "review": return "none";
    case "high_risk": return "allow_one_click_block";
    case "confirmed_threat": return "auto_trash_allowed";
    case "unknown": return "none";
  }
}

function authenticationPassed(envelope: CanonicalEnvelope): boolean {
  const auth = envelope.authentication;
  return auth.dmarc === "pass" || auth.dkim === "pass" || auth.spf === "pass";
}

function boundedContentAllowsSafe(envelope: CanonicalEnvelope): boolean {
  if (envelope.diagnostics.contentCoverage !== "bounded_sufficient") return false;
  if (!authenticationPassed(envelope)) return false;

  const deterministicIdentity =
    Boolean(envelope.listHeaders.listId || envelope.listHeaders.listUnsubscribe) ||
    isOfficialBrandSender(envelope);
  if (!deterministicIdentity) return false;

  const visibleLength = `${envelope.textPreview ?? ""} ${envelope.htmlSignals?.extractedText ?? ""}`.trim().length;
  return visibleLength >= 500;
}

export function scanMessage(
  envelope: CanonicalEnvelope,
  deps: { personalPolicy: PersonalPolicyStore; threatFeed: ThreatFeedCache },
): ScanResult {
  const { result: personalResult, confirmedByPersonalBlock } = personalRulesLayer(envelope, deps.personalPolicy);
  const { result: globalResult, confirmedByGlobalRule } = globalIntelligenceLayer(envelope, deps.threatFeed);

  const layerResults = [
    transportAuthLayer(envelope),
    identityImpersonationLayer(envelope),
    messageIntentLayer(envelope),
    linkStructureLayer(envelope),
    destinationLayerNotRun(),
    attachmentQrLayer(envelope),
    relationshipContextLayer(envelope),
    personalResult,
    globalResult,
  ];

  const scored = computeVerdict({
    parseStatus: envelope.parseStatus,
    layerResults,
    confirmedByRule: confirmedByPersonalBlock || confirmedByGlobalRule,
    boundedContentAllowsSafe: boundedContentAllowsSafe(envelope),
  });

  return { envelope, scored, action: responsePolicy(scored.verdict) };
}
