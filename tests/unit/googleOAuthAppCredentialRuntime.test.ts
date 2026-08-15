import { afterEach, describe, expect, it } from "vitest";
import type {
  CredentialReference,
  CredentialVault,
  CredentialVaultCapabilities,
} from "../../server/src/security/credentialVault.js";
import {
  materializeAdapterConfig,
  secureAdapterConfig,
} from "../../server/src/security/secureAdapterConfig.js";

class TestVault implements CredentialVault {
  readonly values = new Map<string, string>();
  readonly writes: CredentialReference[] = [];

  capabilities(): CredentialVaultCapabilities {
    return {
      backend: "test-native",
      available: true,
      persistent: true,
      userBound: true,
      hardwareBacked: false,
      applicationBound: false,
    };
  }

  async write(reference: CredentialReference, secret: string): Promise<void> {
    this.writes.push({ ...reference });
    this.values.set(`${reference.kind}:${reference.id}`, secret);
  }

  async read(reference: CredentialReference): Promise<string | null> {
    return this.values.get(`${reference.kind}:${reference.id}`) ?? null;
  }

  async delete(reference: CredentialReference): Promise<void> {
    this.values.delete(`${reference.kind}:${reference.id}`);
  }
}

const originalSecret = process.env.EMAIL_SHIELD_GOOGLE_CLIENT_SECRET;

afterEach(() => {
  if (originalSecret === undefined) delete process.env.EMAIL_SHIELD_GOOGLE_CLIENT_SECRET;
  else process.env.EMAIL_SHIELD_GOOGLE_CLIENT_SECRET = originalSecret;
});

describe("guided Gmail application credential continuity", () => {
  it("persists only the mailbox refresh token and rehydrates the app credential at runtime", async () => {
    process.env.EMAIL_SHIELD_GOOGLE_CLIENT_SECRET = "email-shield-google-app-secret";
    const vault = new TestVault();
    const runtimeConfig = {
      provider: "gmail" as const,
      mode: "live" as const,
      credentials: {
        clientId: "desktop.apps.googleusercontent.com",
        clientSecret: "email-shield-google-app-secret",
        refreshToken: "mailbox-refresh-token",
        accountSubject: "stable-google-subject",
      },
    };

    const secured = await secureAdapterConfig(runtimeConfig, vault);

    expect(vault.writes).toHaveLength(1);
    expect(vault.writes[0]?.kind).toBe("oauth-refresh-token");
    expect(JSON.stringify(secured.config)).not.toContain("email-shield-google-app-secret");
    expect(JSON.stringify(secured.config)).not.toContain("mailbox-refresh-token");
    if (secured.config.mode !== "live" || secured.config.provider !== "gmail") {
      throw new Error("Expected secured Gmail live configuration.");
    }
    expect(secured.config.credentials.clientSecret).toBeUndefined();

    const restoredRuntime = await materializeAdapterConfig(secured.config, vault);
    expect(restoredRuntime).toEqual(runtimeConfig);
  });
});
