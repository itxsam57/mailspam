import { describe, expect, it } from "vitest";
import {
  applyProtectionSensitivity,
  defaultProtectionSensitivityPreference,
  evidenceContainsHardSecuritySignal,
  normalizeProtectionSensitivityPreference,
  normalizeProtectionSensitivityProfile,
  type ProtectionSensitivityProfile,
} from "../../server/src/consumer/protectionSensitivity.js";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { relationshipContextLayer } from "../../server/src/engine/layers/relationshipContext.js";
import type { Evidence, ScoredMessage, Verdict } from "../../server/src/engine/verdict.js";

function result(params: {
  verdict: Verdict;
  evidence?: Evidence[];
  confirmedByRule?: boolean;
  action?: "none" | "warn" | "suggest_quarantine" | "allow_one_click_block" | "auto_trash_allowed";
}) {
  const evidence = params.evidence ?? [];
  const scored: ScoredMessage = {
    score: evidence.reduce((sum, item) => sum + Math.max(0, item.scoreContribution), 0),
    evidence,
    verdict: params.verdict,
    confirmedByRule: params.confirmedByRule ?? false,
    layerResults: [],
  };
  return { scored, action: params.action ?? "none" };
}

function relationshipEnvelope(threadContext: CanonicalEnvelope["threadContext"]): CanonicalEnvelope {
  return {
    provider: "gmail",
    accountProof: "account",
    messageId: "message",
    providerNativeId: "native",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Known Sender", address: "sender@example.com", domain: "example.com" },
    replyTo: null,
    subject: "Normal subject",
    date: "2026-08-13T00:00:00.000Z",
    authentication: { spf: "pass", dkim: "pass", dmarc: "pass", arc: "none", providerTrust: "trusted" },
    textPreview: "Normal message",
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext,
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: {
      fetchedAt: "2026-08-13T00:00:00.000Z",
      sizeBytes: 64,
      encoding: "plain",
      contentCoverage: "complete",
    },
  };
}

const profiles: ProtectionSensitivityProfile[] = ["high", "balanced", "low_noise"];

describe("protection sensitivity", () => {
  it("defaults to Balanced and rejects unknown profile/state fields", () => {
    expect(defaultProtectionSensitivityPreference()).toEqual({ schemaVersion: 1, profile: "balanced" });
    expect(normalizeProtectionSensitivityPreference({ schemaVersion: 1, profile: "high" })).toEqual({ schemaVersion: 1, profile: "high" });
    expect(() => normalizeProtectionSensitivityPreference({ schemaVersion: 1, profile: "off" })).toThrow(/invalid/i);
    expect(() => normalizeProtectionSensitivityPreference({ schemaVersion: 1, profile: "balanced", bypassConfirmed: true })).toThrow(/invalid/i);
  });

  it("canonicalizes the consumer High Protection control to the single internal high profile", () => {
    expect(normalizeProtectionSensitivityProfile("high_protection")).toBe("high");
    expect(normalizeProtectionSensitivityPreference({ schemaVersion: 1, profile: "high_protection" })).toEqual({ schemaVersion: 1, profile: "high" });
    expect(normalizeProtectionSensitivityProfile("high")).toBe("high");
  });

  it.each(profiles)("never changes confirmed-threat verdict/action in %s", (profile) => {
    const source = result({ verdict: "confirmed_threat", confirmedByRule: true, action: "auto_trash_allowed" });
    const decision = applyProtectionSensitivity(source, profile);
    expect(decision).toMatchObject({
      profile,
      verdict: "confirmed_threat",
      action: "auto_trash_allowed",
      attention: "critical",
      hardSecuritySignal: true,
    });
    expect(source.scored.verdict).toBe("confirmed_threat");
  });

  it.each(profiles)("never hides a High Risk result in %s", (profile) => {
    const source = result({ verdict: "high_risk", action: "allow_one_click_block" });
    expect(applyProtectionSensitivity(source, profile)).toMatchObject({
      verdict: "high_risk",
      action: "allow_one_click_block",
      attention: "alert",
    });
  });

  it.each([
    ["DMARC_FAIL", "local", 3],
    ["SPF_DKIM_BOTH_FAIL", "local", 2],
    ["BLOCKED_SENDER", "personal_rule", 10],
    ["GLOBAL_CONFIRMED_MATCH", "signed_feed", 10],
    ["FAMILY_CONFIRMED_MATCH", "signed_feed", 10],
  ] as const)("keeps hard signal %s alerting even in Low Noise", (code, source, contribution) => {
    const decision = applyProtectionSensitivity(result({
      verdict: "review",
      evidence: [{ layer: "test", code, description: code, scoreContribution: contribution, source }],
    }), "low_noise");
    expect(decision).toMatchObject({ attention: "alert", hardSecuritySignal: true, reason: "hard_security" });
  });

  it.each([
    [{ isFirstContact: false, threadContinuityBroken: true, replyToChangedMidThread: false }, "THREAD_CONTINUITY_BROKEN"],
    [{ isFirstContact: false, threadContinuityBroken: false, replyToChangedMidThread: true }, "REPLY_TO_CHANGED_MID_THREAD"],
    [{ isFirstContact: false, threadContinuityBroken: false, replyToChangedMidThread: false, relationshipAuthenticationDowngrade: true }, "RELATIONSHIP_AUTH_DOWNGRADE"],
    [{ isFirstContact: false, threadContinuityBroken: false, replyToChangedMidThread: false, replyToChangedFromRelationshipHistory: true }, "RELATIONSHIP_REPLY_TO_CHANGE"],
  ] as const)("treats real relationship evidence %s as non-suppressible", (threadContext, expectedCode) => {
    const layer = relationshipContextLayer(relationshipEnvelope(threadContext));
    expect(layer.evidence.some((item) => item.code === expectedCode)).toBe(true);
    expect(evidenceContainsHardSecuritySignal(layer.evidence)).toBe(true);
    expect(applyProtectionSensitivity(result({ verdict: "review", evidence: layer.evidence }), "low_noise").attention).toBe("alert");
  });

  it("changes only attention for soft Review results", () => {
    const source = result({
      verdict: "review",
      action: "none",
      evidence: [{ layer: "provider_context", code: "JUNK_FOLDER", description: "Provider placed message in Junk.", scoreContribution: 2, source: "local" }],
    });
    expect(applyProtectionSensitivity(source, "high").attention).toBe("alert");
    expect(applyProtectionSensitivity(source, "balanced").attention).toBe("activity");
    expect(applyProtectionSensitivity(source, "low_noise").attention).toBe("none");
    for (const profile of profiles) {
      const decision = applyProtectionSensitivity(source, profile);
      expect(decision.verdict).toBe("review");
      expect(decision.action).toBe("none");
    }
  });

  it("surfaces incomplete/Unknown content only as activity in High Protection", () => {
    const source = result({ verdict: "unknown" });
    expect(applyProtectionSensitivity(source, "high").attention).toBe("activity");
    expect(applyProtectionSensitivity(source, "balanced").attention).toBe("none");
    expect(applyProtectionSensitivity(source, "low_noise").attention).toBe("none");
  });

  it("never turns Safe content into a destructive action", () => {
    for (const profile of profiles) {
      expect(applyProtectionSensitivity(result({ verdict: "safe", action: "none" }), profile)).toMatchObject({
        verdict: "safe",
        action: "none",
        attention: "none",
      });
    }
  });
});