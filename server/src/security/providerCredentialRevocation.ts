import type { CredentialVault } from "./credentialVault.js";
import type { SecureAdapterConfig } from "./secureAdapterConfig.js";
import {
  GoogleOAuthRevocationError,
  revokeGoogleOAuthToken,
} from "../oauth/googleOAuthRevocation.js";

export interface ProviderCredentialRevoker {
  requiresRevocation(config: SecureAdapterConfig): boolean;
  revoke(config: SecureAdapterConfig, vault: CredentialVault): Promise<void>;
}

/**
 * Provider-aware cleanup boundary for long-lived credentials. Native-vault
 * deletion remains SessionStore's responsibility. The revoker resolves the
 * credential from the secure handle so the same provider cleanup works on
 * Windows vault-backed sessions and current-process memory-only compatibility
 * sessions on platforms whose native store is not implemented yet.
 */
export const providerCredentialRevoker: ProviderCredentialRevoker = {
  requiresRevocation(config) {
    return config.mode === "live" &&
      config.provider === "gmail" &&
      Boolean(config.credentials.accountSubject);
  },

  async revoke(config, vault) {
    if (!this.requiresRevocation(config) || config.mode !== "live" || config.provider !== "gmail") return;
    const handle = config.credentials.refreshToken;
    const secret = handle.storage === "memory"
      ? handle.value
      : await vault.read(handle.reference);
    if (!secret) {
      throw new GoogleOAuthRevocationError("The protected Google credential is unavailable for revocation.");
    }
    await revokeGoogleOAuthToken(secret);
  },
};
