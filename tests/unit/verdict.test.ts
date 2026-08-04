import { describe, it, expect } from "vitest";
import { computeVerdict } from "../../server/src/engine/verdict.js";

describe("computeVerdict — structural safety guarantee", () => {
  it("never returns 'safe' when parseStatus is not 'complete', even with zero evidence", () => {
    const result = computeVerdict({
      parseStatus: "partial",
      layerResults: [
        { layer: "transport_auth", applicable: true, evidence: [], incomplete: false },
      ],
      confirmedByRule: false,
    });
    expect(result.verdict).not.toBe("safe");
    expect(result.verdict).toBe("unknown");
  });

  it("never returns 'safe' when a layer is incomplete due to genuinely unavailable content (blocksSafeVerdict)", () => {
    const result = computeVerdict({
      parseStatus: "complete",
      layerResults: [
        {
          layer: "message_intent",
          applicable: true,
          evidence: [],
          incomplete: true,
          incompleteReason: "no body text available",
          blocksSafeVerdict: true,
        },
      ],
      confirmedByRule: false,
    });
    expect(result.verdict).toBe("unknown");
  });

  it("does NOT force 'unknown' when a layer is deliberately not run by design (e.g. destination classification during a scan)", () => {
    const result = computeVerdict({
      parseStatus: "complete",
      layerResults: [
        {
          layer: "destination_classification",
          applicable: true,
          evidence: [],
          incomplete: true,
          incompleteReason: "only runs via explicit Analyze Links action",
          // blocksSafeVerdict intentionally omitted/false
        },
        { layer: "transport_auth", applicable: true, evidence: [], incomplete: false },
      ],
      confirmedByRule: false,
    });
    expect(result.verdict).toBe("safe");
  });

  it("still surfaces high_risk from partial data if evidence is strong enough, rather than downgrading danger", () => {
    const result = computeVerdict({
      parseStatus: "partial",
      layerResults: [
        {
          layer: "identity_impersonation",
          applicable: true,
          incomplete: false,
          evidence: [
            { layer: "identity_impersonation", code: "BRAND_LOOKALIKE_DOMAIN", description: "x", scoreContribution: 5, source: "local" },
            { layer: "identity_impersonation", code: "REPLY_TO_MISMATCH", description: "x", scoreContribution: 2, source: "local" },
          ],
        },
      ],
      confirmedByRule: false,
    });
    expect(result.verdict).toBe("high_risk");
  });

  it("returns 'safe' only when parsing is complete, all layers complete, and evidence is below review threshold", () => {
    const result = computeVerdict({
      parseStatus: "complete",
      layerResults: [
        { layer: "transport_auth", applicable: true, evidence: [], incomplete: false },
        { layer: "identity_impersonation", applicable: true, evidence: [], incomplete: false },
      ],
      confirmedByRule: false,
    });
    expect(result.verdict).toBe("safe");
  });

  it("confirmed_threat short-circuits regardless of parse status", () => {
    const result = computeVerdict({
      parseStatus: "complete",
      layerResults: [],
      confirmedByRule: true,
    });
    expect(result.verdict).toBe("confirmed_threat");
  });
});
