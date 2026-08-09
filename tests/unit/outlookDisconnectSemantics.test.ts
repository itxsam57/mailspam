import { describe, expect, it } from "vitest";
import type { SecureAdapterConfig } from "../../server/src/security/secureAdapterConfig.js";
import { providerCredentialRevoker } from "../../server/src/security/providerCredentialRevocation.js";

describe("Outlook disconnect semantics", () => {
  it("does not route guided Outlook through provider-wide session revocation", () => {
    const config: SecureAdapterConfig = {
      provider: "outlook",
      mode: "live",
      credentials: {
        clientId: "public-client-id",
        accountId: "stable-graph-account-id",
        refreshToken: {
          storage: "vault",
          reference: { id: "outlook-refresh-12345678", kind: "oauth-refresh-token" },
        },
      },
    };
    expect(providerCredentialRevoker.requiresRevocation(config)).toBe(false);
  });
});
