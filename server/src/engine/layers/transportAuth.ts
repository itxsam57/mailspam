import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import type { LayerResult } from "../verdict.js";

/**
 * Layer 1 — Transport and authentication (spec Section 5).
 * Deterministic header parsing only. Never a single signal alone decides
 * safety — this layer only ever produces "review"-weight evidence unless
 * combined with other layers, except an outright DMARC fail plus display
 * name impersonation which is scored higher.
 */
export function transportAuthLayer(envelope: CanonicalEnvelope): LayerResult {
  const evidence: LayerResult["evidence"] = [];
  const auth = envelope.authentication;

  if (auth.dmarc === "fail") {
    evidence.push({
      layer: "transport_auth",
      code: "DMARC_FAIL",
      description: "Message failed DMARC alignment for the claimed sending domain.",
      scoreContribution: 3,
      source: "local",
    });
  }
  if (auth.spf === "fail" && auth.dkim === "fail") {
    evidence.push({
      layer: "transport_auth",
      code: "SPF_DKIM_BOTH_FAIL",
      description: "Both SPF and DKIM failed; sender authenticity could not be verified.",
      scoreContribution: 2,
      source: "local",
    });
  }
  if (auth.spf === "unknown" && auth.dkim === "unknown" && auth.dmarc === "unknown") {
    // Not evidence of danger by itself — but it does mean this layer can't vouch for the message.
    return {
      layer: "transport_auth",
      applicable: true,
      evidence: [],
      incomplete: true,
      incompleteReason: "No authentication headers were available from the provider.",
    };
  }

  return { layer: "transport_auth", applicable: true, evidence, incomplete: false };
}
