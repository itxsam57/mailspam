import { createHash } from "node:crypto";
import type { FixtureFolderOverrides } from "../adapters/fixtures/fixtureAdapter.js";
import type { GmailOAuthCredentials } from "../adapters/gmail/gmailAdapter.js";
import type { ImapCredentials } from "../adapters/imap/imapAdapter.js";
import type { OutlookOAuthCredentials } from "../adapters/outlook/outlookAdapter.js";
import type { Provider } from "../canonical/envelope.js";
import type { AdapterConfig } from "../api/adapterConfig.js";
import {
  type CredentialReference,
  type CredentialVault,
} from "./credentialVault.js";

export interface MemorySecretHandle {
  storage: "memory";
  value: string;
}

export interface VaultSecretHandle {
  storage: "vault";
  reference: CredentialReference;
}

export type SecretHandle = MemorySecretHandle | VaultSecretHandle;

export type SecureAdapterConfig =
  | {
      provider: Provider;
      mode: "fixture";
      fixtureFolderOverrides?: FixtureFolderOverrides;
    }
  | {
      provider: "gmail";
      mode: "live";
      credentials: {
        clientId: string;
        clientSecret?: SecretHandle;
        refreshToken: SecretHandle;
        accountSubject?: string;
      };
    }
  | {
      provider: "outlook";
      mode: "live";
      credentials: {
        clientId: string;
        refreshToken: SecretHandle;
        accountId?: string;
        clientSecret?: SecretHandle;
        tenantId?: string;
      };
    }
  | {
      provider: "icloud" | "yahoo";
      mode: "live";
      credentials: {
        user: string;
        appPassword: SecretHandle;
      };
    }
  | {
      provider: "imap";
      mode: "live";
      credentials: {
        host: string;
        port: number;
        secure: boolean;
        user: string;
        appPassword: SecretHandle;
      };
    };

export interface SecuredAdapterConfigResult {
  config: SecureAdapterConfig;
  vaultReferences: CredentialReference[];
}

type HostedAppPasswordConfig = {
  provider: "icloud" | "yahoo";
  mode: "live";
  credentials: { user: string; appPassword: string };
};

type GenericImapAppPasswordConfig = {
  provider: "imap";
  mode: "live";
  credentials: ImapCredentials;
};

type AppPasswordRuntimeConfig = HostedAppPasswordConfig | GenericImapAppPasswordConfig;
type GmailRuntimeConfig = Extract<AdapterConfig, { provider: "gmail"; mode: "live" }>;
type OutlookRuntimeConfig = Extract<AdapterConfig, { provider: "outlook"; mode: "live" }>;

const APP_PASSWORD_REFERENCE_NAMESPACE = "email-shield-app-password-account-v1\0";
const GMAIL_REFRESH_REFERENCE_NAMESPACE = "email-shield-gmail-refresh-account-v1\0";
const OUTLOOK_REFRESH_REFERENCE_NAMESPACE = "email-shield-outlook-refresh-account-v1\0";

function memorySecret(value: string): MemorySecretHandle {
  return { storage: "memory", value };
}

function appPasswordAccountIdentity(config: AppPasswordRuntimeConfig): string {
  switch (config.provider) {
    case "icloud":
    case "yahoo":
      return `${config.provider}:${config.credentials.user.trim().toLowerCase()}`;
    case "imap":
      return `imap:${config.credentials.host.trim().toLowerCase()}:${config.credentials.port}:${config.credentials.user.trim().toLowerCase()}`;
  }
}

/**
 * A deterministic opaque reference lets the same mailbox reuse one protected
 * credential across reconnects without exposing mailbox metadata in Credential
 * Manager or accumulating random orphaned records after process restarts.
 */
export function appPasswordCredentialReference(config: AppPasswordRuntimeConfig): CredentialReference {
  const id = createHash("sha256")
    .update(APP_PASSWORD_REFERENCE_NAMESPACE, "utf8")
    .update(appPasswordAccountIdentity(config), "utf8")
    .digest("hex");
  return { id: `app-password-${id}`, kind: "imap-app-password" };
}

/** Guided Gmail OAuth uses Google's verified OIDC `sub` as stable identity. */
export function gmailRefreshTokenCredentialReference(
  clientId: string,
  accountSubject: string,
): CredentialReference {
  const normalizedClientId = clientId.trim();
  const normalizedSubject = accountSubject.trim();
  if (!normalizedClientId || !normalizedSubject) {
    throw new Error("A stable Gmail OAuth client and account subject are required.");
  }
  const id = createHash("sha256")
    .update(GMAIL_REFRESH_REFERENCE_NAMESPACE, "utf8")
    .update(normalizedClientId, "utf8")
    .update("\0", "utf8")
    .update(normalizedSubject, "utf8")
    .digest("hex");
  return { id: `gmail-refresh-${id}`, kind: "oauth-refresh-token" };
}

/** Guided Outlook OAuth uses Microsoft Graph `/me.id`, never the rotating token. */
export function outlookRefreshTokenCredentialReference(
  clientId: string,
  accountId: string,
): CredentialReference {
  const normalizedClientId = clientId.trim();
  const normalizedAccountId = accountId.trim();
  if (!normalizedClientId || !normalizedAccountId) {
    throw new Error("A stable Microsoft OAuth client and Graph account ID are required.");
  }
  const id = createHash("sha256")
    .update(OUTLOOK_REFRESH_REFERENCE_NAMESPACE, "utf8")
    .update(normalizedClientId, "utf8")
    .update("\0", "utf8")
    .update(normalizedAccountId, "utf8")
    .digest("hex");
  return { id: `outlook-refresh-${id}`, kind: "oauth-refresh-token" };
}

/**
 * Synchronous memory-only protection used by fixtures, tests, legacy developer
 * credentials, and platforms without an implemented native persistent vault.
 * It never writes a secret to disk.
 */
export function secureAdapterConfigInMemory(config: AdapterConfig): SecuredAdapterConfigResult {
  if (config.mode === "fixture") {
    const fixtureFolderOverrides = config.fixtureFolderOverrides ?? {};
    config.fixtureFolderOverrides = fixtureFolderOverrides;
    return {
      config: { provider: config.provider, mode: "fixture", fixtureFolderOverrides },
      vaultReferences: [],
    };
  }

  switch (config.provider) {
    case "gmail":
      return {
        config: {
          provider: "gmail",
          mode: "live",
          credentials: {
            clientId: config.credentials.clientId,
            clientSecret: config.credentials.clientSecret ? memorySecret(config.credentials.clientSecret) : undefined,
            refreshToken: memorySecret(config.credentials.refreshToken),
            accountSubject: config.credentials.accountSubject,
          },
        },
        vaultReferences: [],
      };
    case "outlook":
      return {
        config: {
          provider: "outlook",
          mode: "live",
          credentials: {
            clientId: config.credentials.clientId,
            refreshToken: memorySecret(config.credentials.refreshToken),
            accountId: config.credentials.accountId,
            clientSecret: config.credentials.clientSecret ? memorySecret(config.credentials.clientSecret) : undefined,
            tenantId: config.credentials.tenantId,
          },
        },
        vaultReferences: [],
      };
    case "icloud":
    case "yahoo":
      return {
        config: {
          provider: config.provider,
          mode: "live",
          credentials: {
            user: config.credentials.user,
            appPassword: memorySecret(config.credentials.appPassword),
          },
        },
        vaultReferences: [],
      };
    case "imap":
      return {
        config: {
          provider: "imap",
          mode: "live",
          credentials: {
            host: config.credentials.host,
            port: config.credentials.port,
            secure: config.credentials.secure,
            user: config.credentials.user,
            appPassword: memorySecret(config.credentials.appPassword),
          },
        },
        vaultReferences: [],
      };
  }
}

async function secureGuidedGmail(
  config: GmailRuntimeConfig,
  vault: CredentialVault,
): Promise<SecuredAdapterConfigResult> {
  const accountSubject = config.credentials.accountSubject?.trim();
  if (!accountSubject) return secureAdapterConfigInMemory(config);

  const reference = gmailRefreshTokenCredentialReference(config.credentials.clientId, accountSubject);
  await vault.write(reference, config.credentials.refreshToken);
  return {
    config: {
      provider: "gmail",
      mode: "live",
      credentials: {
        clientId: config.credentials.clientId,
        // The Google Desktop client credential belongs to the Email Shield
        // application, not this mailbox. It must not enter the per-mailbox
        // encrypted connection registry. materializeAdapterConfig rehydrates it
        // from process-local application configuration when the adapter runs.
        refreshToken: { storage: "vault", reference },
        accountSubject,
      },
    },
    vaultReferences: [reference],
  };
}

async function secureGuidedOutlook(
  config: OutlookRuntimeConfig,
  vault: CredentialVault,
): Promise<SecuredAdapterConfigResult> {
  const accountId = config.credentials.accountId?.trim();
  if (!accountId) return secureAdapterConfigInMemory(config);

  const reference = outlookRefreshTokenCredentialReference(config.credentials.clientId, accountId);
  await vault.write(reference, config.credentials.refreshToken);
  return {
    config: {
      provider: "outlook",
      mode: "live",
      credentials: {
        clientId: config.credentials.clientId,
        refreshToken: { storage: "vault", reference },
        accountId,
        clientSecret: config.credentials.clientSecret ? memorySecret(config.credentials.clientSecret) : undefined,
        tenantId: config.credentials.tenantId,
      },
    },
    vaultReferences: [reference],
  };
}

/**
 * Protect provider credentials with the native vault when one is available.
 * There is deliberately no plaintext persistence fallback. Guided OAuth paths
 * are vault-eligible only after their provider returns a verified stable account
 * identifier; legacy developer credentials stay process-memory-only.
 */
export async function secureAdapterConfig(
  config: AdapterConfig,
  vault: CredentialVault,
): Promise<SecuredAdapterConfigResult> {
  if (config.mode !== "live" || !vault.capabilities().available) {
    return secureAdapterConfigInMemory(config);
  }

  switch (config.provider) {
    case "gmail":
      return secureGuidedGmail(config, vault);
    case "outlook":
      return secureGuidedOutlook(config, vault);
    case "icloud":
    case "yahoo": {
      const reference = appPasswordCredentialReference(config);
      await vault.write(reference, config.credentials.appPassword);
      return {
        config: {
          provider: config.provider,
          mode: "live",
          credentials: { user: config.credentials.user, appPassword: { storage: "vault", reference } },
        },
        vaultReferences: [reference],
      };
    }
    case "imap": {
      const reference = appPasswordCredentialReference(config);
      await vault.write(reference, config.credentials.appPassword);
      return {
        config: {
          provider: "imap",
          mode: "live",
          credentials: {
            host: config.credentials.host,
            port: config.credentials.port,
            secure: config.credentials.secure,
            user: config.credentials.user,
            appPassword: { storage: "vault", reference },
          },
        },
        vaultReferences: [reference],
      };
    }
  }
}

async function materializeSecret(handle: SecretHandle, vault: CredentialVault): Promise<string> {
  if (handle.storage === "memory") {
    if (!handle.value) throw new Error("The in-memory provider credential is no longer available. Reconnect the account.");
    return handle.value;
  }
  const secret = await vault.read(handle.reference);
  if (!secret) throw new Error("The protected provider credential is unavailable. Reconnect the account.");
  return secret;
}

/** Persist a Microsoft replacement refresh token into the existing account handle. */
export async function replaceSecureOutlookRefreshToken(
  config: Extract<SecureAdapterConfig, { provider: "outlook"; mode: "live" }>,
  vault: CredentialVault,
  refreshToken: string,
): Promise<void> {
  if (!refreshToken) throw new Error("A replacement Microsoft refresh token is required.");
  const handle = config.credentials.refreshToken;
  if (handle.storage === "memory") {
    handle.value = refreshToken;
    return;
  }
  await vault.write(handle.reference, refreshToken);
}

/** Raw provider secrets exist only immediately before adapter/provider use. */
export async function materializeAdapterConfig(
  config: SecureAdapterConfig,
  vault: CredentialVault,
): Promise<AdapterConfig> {
  if (config.mode === "fixture") {
    return {
      provider: config.provider,
      mode: "fixture",
      fixtureFolderOverrides: config.fixtureFolderOverrides,
    };
  }

  switch (config.provider) {
    case "gmail": {
      const clientSecret = config.credentials.clientSecret
        ? await materializeSecret(config.credentials.clientSecret, vault)
        : process.env.EMAIL_SHIELD_GOOGLE_CLIENT_SECRET?.trim() || undefined;
      const credentials: GmailOAuthCredentials = {
        clientId: config.credentials.clientId,
        clientSecret,
        refreshToken: await materializeSecret(config.credentials.refreshToken, vault),
        accountSubject: config.credentials.accountSubject,
      };
      return { provider: "gmail", mode: "live", credentials };
    }
    case "outlook": {
      const credentials: OutlookOAuthCredentials = {
        clientId: config.credentials.clientId,
        refreshToken: await materializeSecret(config.credentials.refreshToken, vault),
        accountId: config.credentials.accountId,
        clientSecret: config.credentials.clientSecret ? await materializeSecret(config.credentials.clientSecret, vault) : undefined,
        tenantId: config.credentials.tenantId,
      };
      return { provider: "outlook", mode: "live", credentials };
    }
    case "icloud":
    case "yahoo":
      return {
        provider: config.provider,
        mode: "live",
        credentials: {
          user: config.credentials.user,
          appPassword: await materializeSecret(config.credentials.appPassword, vault),
        },
      };
    case "imap": {
      const credentials: ImapCredentials = {
        host: config.credentials.host,
        port: config.credentials.port,
        secure: config.credentials.secure,
        user: config.credentials.user,
        appPassword: await materializeSecret(config.credentials.appPassword, vault),
      };
      return { provider: "imap", mode: "live", credentials };
    }
  }
}

export function releaseMemorySecrets(config: SecureAdapterConfig): void {
  if (config.mode !== "live") return;
  const release = (handle: SecretHandle | undefined) => {
    if (handle?.storage === "memory") handle.value = "";
  };

  switch (config.provider) {
    case "gmail":
      release(config.credentials.clientSecret);
      release(config.credentials.refreshToken);
      break;
    case "outlook":
      release(config.credentials.clientSecret);
      release(config.credentials.refreshToken);
      break;
    case "icloud":
    case "yahoo":
    case "imap":
      release(config.credentials.appPassword);
      break;
  }
}
