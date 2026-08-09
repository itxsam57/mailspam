import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import type { LayerResult } from "../verdict.js";

/**
 * Layer 7 — Relationship context (spec Section 5).
 * Local-only mailbox-derived history — never sent anywhere. Established
 * history is contextual evidence, never an allowlist and never sufficient to
 * override personal/global confirmed-threat rules or strong current-message
 * evidence.
 */
export function relationshipContextLayer(envelope: CanonicalEnvelope): LayerResult {
  const evidence: LayerResult["evidence"] = [];
  const ctx = envelope.threadContext;

  if (ctx.threadContinuityBroken) {
    evidence.push({
      layer: "relationship_context",
      code: "THREAD_CONTINUITY_BROKEN",
      description: "Message claims to continue an existing thread but the local reference chain doesn't match prior history.",
      scoreContribution: 3,
      source: "local",
    });
  }

  if (ctx.replyToChangedMidThread) {
    evidence.push({
      layer: "relationship_context",
      code: "REPLY_TO_CHANGED_MID_THREAD",
      description: "Reply-To address changed partway through an existing conversation thread.",
      scoreContribution: 4,
      source: "local",
    });
  }

  if (ctx.relationshipAuthenticationDowngrade) {
    evidence.push({
      layer: "relationship_context",
      code: "RELATIONSHIP_AUTH_DOWNGRADE",
      description: "An established locally observed sender that was previously authenticated now has an explicit authentication failure.",
      scoreContribution: 3,
      source: "local",
    });
  }

  if (ctx.replyToChangedFromRelationshipHistory) {
    evidence.push({
      layer: "relationship_context",
      code: "RELATIONSHIP_REPLY_TO_CHANGE",
      description: "An established sender changed a previously stable Reply-To destination.",
      scoreContribution: 3,
      source: "local",
    });
  }

  const priorMessages = ctx.relationshipPriorMessages ?? 0;
  const priorSuspicious = ctx.relationshipPriorSuspiciousMessages ?? 0;
  if (priorMessages >= 3 && priorSuspicious >= 2 && priorSuspicious * 2 >= priorMessages) {
    evidence.push({
      layer: "relationship_context",
      code: "REPEATED_SUSPICIOUS_RELATIONSHIP_HISTORY",
      description: "Most prior locally observed messages from this sender already required review or stronger protection.",
      scoreContribution: 2,
      source: "local",
    });
  }

  if (ctx.hasEstablishedSenderHistory) {
    evidence.push({
      layer: "relationship_context",
      code: "ESTABLISHED_LOCAL_SENDER_HISTORY",
      description: "This sender has conservative established local history based on multiple prior benign authenticated observations.",
      scoreContribution: 0,
      source: "local",
    });
  } else if (ctx.isFirstContact) {
    evidence.push({
      layer: "relationship_context",
      code: "FIRST_CONTACT",
      description: "No conservative established sender relationship exists in local history.",
      scoreContribution: 0,
      source: "local",
    });
  }

  return { layer: "relationship_context", applicable: true, evidence, incomplete: false };
}
