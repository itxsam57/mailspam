import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import type { LayerResult } from "../verdict.js";

/**
 * Layer 7 — Relationship context (spec Section 5).
 * Local-only mailbox history — never sent anywhere. First-contact alone is
 * not evidence of danger (most legitimate mail is first-contact); it only
 * contributes when paired with other layers' findings, so this layer's
 * evidence carries deliberately small weight and mainly exists to give the
 * "conversation hijacking" pattern (broken thread continuity + changed
 * reply-to on an existing thread) real signal.
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

  // First contact alone: negligible weight, informational only.
  if (ctx.isFirstContact) {
    evidence.push({
      layer: "relationship_context",
      code: "FIRST_CONTACT",
      description: "No prior successful exchange with this sender in local history.",
      scoreContribution: 0,
      source: "local",
    });
  }

  return { layer: "relationship_context", applicable: true, evidence, incomplete: false };
}
