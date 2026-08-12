import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import type { LayerResult } from "../verdict.js";

/**
 * Provider placement is corroborating evidence, never a confirmed-threat rule.
 * Every adapter reaches this layer only after mapping native folder semantics to
 * the provider-neutral CanonicalEnvelope folder contract.
 */
export function providerContextLayer(envelope: CanonicalEnvelope): LayerResult {
  const evidence: LayerResult["evidence"] = [];
  if (envelope.folder === "spam") {
    evidence.push({
      layer: "provider_context",
      code: "PROVIDER_SPAM_JUNK_PLACEMENT",
      description: "The provider placed this message in its Spam/Junk folder; this corroborates other evidence but is not conclusive by itself.",
      scoreContribution: 2,
      source: "local",
    });
  }
  return { layer: "provider_context", applicable: true, evidence, incomplete: false };
}
