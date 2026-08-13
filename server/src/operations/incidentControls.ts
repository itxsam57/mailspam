export interface IncidentNetworkControls {
  communityClientNetworkEnabled: boolean;
  linkAnalysisNetworkEnabled: boolean;
  accountSyncNetworkEnabled: boolean;
}

function enabledUnlessDisabled(value: string | undefined): boolean {
  return value?.trim() !== "1";
}

/**
 * Operator-controlled network kill switches. These controls disable only the
 * named outbound/shared network surface. They do not disable the deterministic
 * local scanner, local personal policy, local mailbox actions or local Scam
 * Check logic.
 */
export function incidentNetworkControlsFromEnvironment(
  environment: NodeJS.ProcessEnv = process.env,
): IncidentNetworkControls {
  return {
    communityClientNetworkEnabled: enabledUnlessDisabled(environment.EMAIL_SHIELD_DISABLE_COMMUNITY_CLIENT_NETWORK),
    linkAnalysisNetworkEnabled: enabledUnlessDisabled(environment.EMAIL_SHIELD_DISABLE_LINK_ANALYSIS_NETWORK),
    accountSyncNetworkEnabled: enabledUnlessDisabled(environment.EMAIL_SHIELD_DISABLE_ACCOUNT_SYNC_NETWORK),
  };
}
