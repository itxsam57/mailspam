import type { CanonicalEnvelope } from "../../canonical/envelope.js";
import type { LayerResult } from "../verdict.js";

/**
 * Structural HTML-email interaction evidence. This layer never executes HTML,
 * submits forms, follows redirects or interprets arbitrary script. It consumes
 * only the bounded canonical observations produced during MIME normalization.
 */
export function htmlInteractionLayer(envelope: CanonicalEnvelope): LayerResult {
  const html = envelope.htmlSignals;
  if (!html) {
    return { layer: "html_interaction", applicable: false, evidence: [], incomplete: false };
  }

  const evidence: LayerResult["evidence"] = [];
  const formActionPresent = envelope.links.some((link) => link.interaction === "form_action");

  if (html.hasForm && html.hasPasswordField) {
    evidence.push({
      layer: "html_interaction",
      code: "EMBEDDED_PASSWORD_FORM",
      description: formActionPresent
        ? "Email HTML embeds a password-entry form with a submission destination."
        : "Email HTML embeds a password-entry form directly in message content.",
      scoreContribution: formActionPresent ? 3 : 2,
      source: "local",
    });
  }

  return {
    layer: "html_interaction",
    applicable: true,
    evidence,
    incomplete: false,
  };
}
