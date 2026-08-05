import type { CanonicalEnvelope } from "../canonical/envelope.js";
import { computeVerdict, type ScoredMessage, type Verdict } from "./verdict.js";
import {
  authenticationPassed,
  hasAuthenticatedOrganizationalIdentity,
} from "./identitySignals.js";
import { transportAuthLayer } from "./layers/transportAuth.js";
import { identityImpersonationLayer } from "./layers/identityImpersonation.js";
import { messageIntentLayer } from "./layers/messageIntent.js";
import { linkStructureLayer } from "./layers/linkStructure.js";
import { destinationLayerNotRun } from "./layers/destinationClassification.js";
import { attachmentQrLayer } from "./layers/attachmentQr.js";
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
