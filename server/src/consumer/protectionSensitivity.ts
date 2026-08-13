import type { ScanResult } from "../engine/pipeline.js";
import type { Evidence, Verdict } from "../engine/verdict.js";

export const PROTECTION_SENSITIVITY_SCHEMA_VERSION = 1 as const;

export type ProtectionSensitivityProfile = "high" | "balanced" | "low_noise";
export type ProtectionAttention = "none" | "activity" | "alert" | "critical";

export interface ProtectionSensitivityPreferenceV1 {
  schemaVersion: typeof PROTECTION_SENSITIVITY_SCHEMA_VERSION;
  profile: ProtectionSensitivityProfile;
}

export interface ProtectionPresentationDecision {
  profile: ProtectionSensitivityProfile;
  /** Authoritative engine result is copied through unchanged. */
  verdict: Verdict;
  action: ScanResult["action"];
  attention: ProtectionAttention;
  hardSecuritySignal: boolean;
  reason: "safe" | "unknown" | "soft_review" | "hard_security" | "high_risk" | "confirmed_threat";
}

/**
 * Evidence classes that Low Noise is never allowed to hide. Keep these names
 * aligned to evidence emitted by the authoritative engine; regression tests
 * exercise the real layer producers for relationship-compromise signals.
 */
const HARD_SECURITY_CODES = new Set([
  "DMARC_FAIL",
  "SPF_DKIM_BOTH_FAIL",
  "BLOCKED_SENDER",
  "BLOCKED_DOMAIN",
  "LOCALLY_REPORTED_SCAM_CAMPAIGN",
  "GLOBAL_CONFIRMED_MATCH",
  "FAMILY_CONFIRMED_MATCH",
  "SIGNED_IDENTITY_DOMAIN_MISMATCH",
  "THREAD_CONTINUITY_BROKEN",
  "REPLY_TO_CHANGED_MID_THREAD",
  "RELATIONSHIP_AUTH_DOWNGRADE",
  "RELATIONSHIP_REPLY_TO_CHANGE",
]);

export function normalizeProtectionSensitivityProfile(value: unknown): ProtectionSensitivityProfile {
  // Consumer-facing controls use the descriptive "high_protection" value,
  // while persistence and the engine intentionally keep the canonical "high"
  // profile. Canonicalize only at this input boundary so stored/runtime state
  // never gains a second spelling for the same protection policy.
  if (value === "high_protection") return "high";
  if (value === "high" || value === "balanced" || value === "low_noise") return value;
  throw new Error("Protection sensitivity profile is invalid.");
}

export function normalizeProtectionSensitivityPreference(input: unknown): ProtectionSensitivityPreferenceV1 {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Protection sensitivity preference is invalid.");
  const value = input as Record<string, unknown>;
  if (Object.keys(value).some((key) => key !== "schemaVersion" && key !== "profile")
    || value.schemaVersion !== PROTECTION_SENSITIVITY_SCHEMA_VERSION) {
    throw new Error("Protection sensitivity preference is invalid.");
  }
  return {
    schemaVersion: PROTECTION_SENSITIVITY_SCHEMA_VERSION,
    profile: normalizeProtectionSensitivityProfile(value.profile),
  };
}

export function evidenceContainsHardSecuritySignal(evidence: readonly Evidence[]): boolean {
  return evidence.some((item) =>
    HARD_SECURITY_CODES.has(item.code)
    || item.source === "personal_rule" && item.scoreContribution >= 10
    || item.source === "signed_feed" && item.scoreContribution >= 10,
  );
}

/**
 * Sensitivity is presentation/notification policy only. It cannot rewrite the
 * authoritative verdict, score, action or evidence produced by the engine.
 */
export function applyProtectionSensitivity(
  result: Pick<ScanResult, "action" | "scored">,
  profile: ProtectionSensitivityProfile,
): ProtectionPresentationDecision {
  const normalizedProfile = normalizeProtectionSensitivityProfile(profile);
  const verdict = result.scored.verdict;
  const hardSecuritySignal = result.scored.confirmedByRule
    || evidenceContainsHardSecuritySignal(result.scored.evidence);

  if (verdict === "confirmed_threat") {
    return { profile: normalizedProfile, verdict, action: result.action, attention: "critical", hardSecuritySignal: true, reason: "confirmed_threat" };
  }
  if (verdict === "high_risk") {
    return { profile: normalizedProfile, verdict, action: result.action, attention: "alert", hardSecuritySignal, reason: "high_risk" };
  }
  if (hardSecuritySignal) {
    // A hard contradiction can exist in a Review result when it is the only
    // strong signal. Low Noise may not hide it.
    return { profile: normalizedProfile, verdict, action: result.action, attention: "alert", hardSecuritySignal: true, reason: "hard_security" };
  }
  if (verdict === "review") {
    const attention: ProtectionAttention = normalizedProfile === "high"
      ? "alert"
      : normalizedProfile === "balanced"
        ? "activity"
        : "none";
    return { profile: normalizedProfile, verdict, action: result.action, attention, hardSecuritySignal: false, reason: "soft_review" };
  }
  if (verdict === "unknown") {
    const attention: ProtectionAttention = normalizedProfile === "high" ? "activity" : "none";
    return { profile: normalizedProfile, verdict, action: result.action, attention, hardSecuritySignal: false, reason: "unknown" };
  }
  return { profile: normalizedProfile, verdict, action: result.action, attention: "none", hardSecuritySignal: false, reason: "safe" };
}

export function defaultProtectionSensitivityPreference(): ProtectionSensitivityPreferenceV1 {
  return { schemaVersion: PROTECTION_SENSITIVITY_SCHEMA_VERSION, profile: "balanced" };
}
