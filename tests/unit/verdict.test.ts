import { describe, it, expect } from "vitest";
import { computeVerdict } from "../../server/src/engine/verdict.js";

const evidence = (code: string, scoreContribution: number) => ({
  layer: "identity_impersonation",
  code,
  description: code,
  scoreContribution,
  source: "local" as const,
});

describe("computeVerdict — structural safety guarantee", () => {
  it("never returns Safe when parsing is partial and no evidence is available by default", () => {
    const result = computeVerdict({
      parseStatus: "partial",
      layerResults: [{ layer: "transport_auth", applicable: true, evidence: [], incomplete: false }],
      confirmedByRule: false,
    });
    expect(result.verdict).toBe("unknown");
  });

  it("allows Safe only when the pipeline explicitly approves bounded content", () => {
    const result = computeVerdict({
      parseStatus: "partial",
      layerResults: [{ layer: "transport_auth", applicable: true, evidence: [], incomplete: false }],
      confirmedByRule: false,
      boundedContentAllowsSafe: true,
    });
    expect(result.verdict).toBe("safe");
  });

  it("keeps unavailable content Unknown without an exact user decision", () => {
    const result = computeVerdict({
      parseStatus: "complete",
      layerResults: [{
        layer: "message_intent",
        applicable: true,
        evidence: [],
        incomplete: true,
        incompleteReason: "no body text available",
        blocksSafeVerdict: true,
      }],
      confirmedByRule: false,
      boundedContentAllowsSafe: true,
    });
    expect(result.verdict).toBe("unknown");
  });

  it("allows an explicit exact-message approval to override ordinary uncertainty", () => {
    const result = computeVerdict({
      parseStatus: "partial",
      layerResults: [{
        layer: "message_intent",
        applicable: true,
        evidence: [evidence("HEURISTIC_REVIEW", 3)],
        incomplete: true,
        blocksSafeVerdict: true,
      }],
      confirmedByRule: false,
      exactMessageApprovedByUser: true,
    });
    expect(result.verdict).toBe("safe");
  });

  it("never lets exact-message approval override a confirmed rule", () => {
    const result = computeVerdict({
      parseStatus: "partial",
      layerResults: [],
      confirmedByRule: true,
      exactMessageApprovedByUser: true,
    });
    expect(result.verdict).toBe("confirmed_threat");
  });

  it("does not force Unknown when a layer is deliberately deferred by design", () => {
    const result = computeVerdict({
      parseStatus: "complete",
      layerResults: [
        {
          layer: "destination_classification",
          applicable: true,
          evidence: [],
          incomplete: true,
          incompleteReason: "only runs via explicit Analyze Links action",
        },
        { layer: "transport_auth", applicable: true, evidence: [], incomplete: false },
      ],
      confirmedByRule: false,
    });
    expect(result.verdict).toBe("safe");
  });

  it("preserves Review for partial messages with moderate evidence", () => {
    const result = computeVerdict({
      parseStatus: "partial",
      layerResults: [{
        layer: "identity_impersonation",
        applicable: true,
        incomplete: false,
        evidence: [evidence("BRAND_DOMAIN_MISMATCH", 3)],
      }],
      confirmedByRule: false,
    });
    expect(result.score).toBe(3);
    expect(result.verdict).toBe("review");
  });

  it("preserves High Risk for partial messages with strong evidence", () => {
    const result = computeVerdict({
      parseStatus: "partial",
      layerResults: [{
        layer: "identity_impersonation",
        applicable: true,
        incomplete: false,
        evidence: [evidence("BRAND_DOMAIN_MISMATCH", 3), evidence("CALLBACK_SCAM_INTENT", 4)],
      }],
      confirmedByRule: false,
    });
    expect(result.score).toBe(7);
    expect(result.verdict).toBe("high_risk");
  });

  it("returns Safe when parsing is complete and evidence is below Review", () => {
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

  it("Confirmed Threat short-circuits regardless of parse status", () => {
    const result = computeVerdict({ parseStatus: "partial", layerResults: [], confirmedByRule: true });
    expect(result.verdict).toBe("confirmed_threat");
  });
});
