import type { CredentialReference } from "./credentialVault.js";
import type { SecureAdapterConfig } from "./secureAdapterConfig.js";
import { revokeGoogleOAuthToken } from "../oauth/googleOAuthRevocation.js";

export interface ProviderCredentialRevoker {
  requiresRevocation(config: SecureAdapterConfig, reference: CredentialReference): boolean;
  revoke(config: SecureAdapterConfig, reference: CredentialReference, secret: string): Promise<void>;
}

/**
 * Provider-aware cleanup boundary for long-lived credentials. Only credentials
 * whose provider supports and requires an explicit remote revocation are marked
 * here. Native-vault deletion remains SessionStore's responsibility.
 */
export const providerCredentialRevoker: ProviderCredentialRevoker = {
  requiresRevocation(config, reference) {
    return config.mode === "live" &&
      config.provider === "gmail" &&
      Boolean(config.credentials.accountSubject) &&
      reference.kind === "oauth-refresh-token";
  },

  async revoke(config, reference, secret) {
    if (!this.requiresRevocation(config, reference)) return;
    await revokeGoogleOAuthToken(secret);
  },
};
