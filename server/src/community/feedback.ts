export const USER_REPORTED_SCAM_CODE = "USER_REPORTED_SCAM";
export const USER_BLOCKED_MESSAGE_CODE = "USER_BLOCKED_MESSAGE";
export const USER_CONFIRMED_LEGITIMATE_CODE = "USER_CONFIRMED_LEGITIMATE";

/**
 * Positive consensus is intentionally harder to establish than a threat
 * warning. It can only suppress weak review context; it is never an allowlist.
 */
export const LEGITIMATE_CONSENSUS_REPORTERS = 10;
export const LEGITIMATE_RULE_PREFIX = "community-legitimate:";

export function hasLegitimateFeedback(codes: readonly string[]): boolean {
  return codes.includes(USER_CONFIRMED_LEGITIMATE_CODE);
}

export function hasBlockFeedback(codes: readonly string[]): boolean {
  return codes.includes(USER_BLOCKED_MESSAGE_CODE);
}

export function hasExplicitScamFeedback(codes: readonly string[]): boolean {
  return codes.includes(USER_REPORTED_SCAM_CODE);
}
