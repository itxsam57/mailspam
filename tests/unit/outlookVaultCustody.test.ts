import { describe, expect, it } from "vitest";
import type { AdapterConfig } from "../../server/src/api/adapterConfig.js";
import type { CredentialReference, CredentialVault, CredentialVaultCapabilities } from "../../server/src/security/credentialVault.js";
import { secureAdapterConfig } from "../../server/src/security/secureAdapterConfig.js";

const guidedOutlook: AdapterConfig = {
  provider: "outlook",
  mode: "live",
  credentials: {
    clientId: "public-client-id",
    refreshToken: "refresh-token-private",
    accountId: "stable-graph-account-id",
  },
};

class FailingNativeVault implements CredentialVault {
  capabilities(): CredentialVaultCapabilities {
    return {
      backend: "failing-native",
      available: true,
      persistent: true,
      userBound: true,
      hardwareBacked: false,
      applicationBound: false,
    };
  }
  async write(_reference: CredentialReference, _secret: string): Promise<void> { throw new Error("native vault write failed"); }
  async read(_reference: CredentialReference): Promise<string | null> { return null; }
  async delete(_reference: CredentialReference): Promise<void> {}
}

class UnsupportedVault implements CredentialVault {
  writes = 0;
  capabilities(): CredentialVaultCapabilities {
    return {
      backend: "unsupported:test",
      available: false,
      persistent: false,
      userBound: false,
      hardwareBacked: false,
      applicationBound: false,
    };
  }
  async write(_reference: CredentialReference, _secret: string): Promise<void> { this.writes += 1; throw new Error("must not write"); }
  async read(_reference: CredentialReference): Promise<string | null> { return null; }
  async delete(_reference: CredentialReference): Promise<void> {}
}

describe("guided Outlook secure custody boundary", () => {
  it("fails closed when a present native vault cannot persist the initial refresh token", async () => {
    await expect(secureAdapterConfig(structuredClone(guidedOutlook), new FailingNativeVault()))
      .rejects.toThrow(/native vault write failed/i);
  });

  it("uses process-memory-only custody when no native backend exists and never attempts plaintext persistence", async () => {
    const vault = new UnsupportedVault();
    const secured = await secureAdapterConfig(structuredClone(guidedOutlook), vault);
    expect(vault.writes).toBe(0);
    expect(secured.vaultReferences).toHaveLength(0);
    expect(secured.config.mode).toBe("live");
    if (secured.config.mode === "live" && secured.config.provider === "outlook") {
      expect(secured.config.credentials.refreshToken.storage).toBe("memory");
      expect(secured.config.credentials.accountId).toBe("stable-graph-account-id");
    }
  });
});
