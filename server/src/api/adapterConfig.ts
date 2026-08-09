import type { Provider } from "../canonical/envelope.js";
import type {
  EmailAdapter,
  FetchPage,
  FolderDescriptor,
  SpamReportResult,
} from "../canonical/adapter.js";
import { buildDemoMailbox } from "../adapters/fixtures/demoMailbox.js";
import type { FixtureFolderOverrides } from "../adapters/fixtures/fixtureAdapter.js";
import { GmailAdapter, type GmailOAuthCredentials } from "../adapters/gmail/gmailAdapter.js";
import { OutlookAdapter, type OutlookOAuthCredentials, type OutlookRefreshTokenSink } from "../adapters/outlook/outlookAdapter.js";
import { createGenericImapAdapter, createIcloudAdapter, createYahooAdapter, type ImapCredentials } from "../adapters/imap/imapAdapter.js";
import type { CredentialVault } from "../security/credentialVault.js";
import { createCredentialVault } from "../security/credentialVaultFactory.js";
import {
  materializeAdapterConfig,
  replaceSecureOutlookRefreshToken,
  type SecureAdapterConfig,
} from "../security/secureAdapterConfig.js";

export type AdapterConfig =
  | { provider: Provider; mode: "fixture"; fixtureFolderOverrides?: FixtureFolderOverrides }
  | { provider: "gmail"; mode: "live"; credentials: GmailOAuthCredentials }
  | { provider: "outlook"; mode: "live"; credentials: OutlookOAuthCredentials }
  | { provider: "icloud" | "yahoo"; mode: "live"; credentials: { user: string; appPassword: string } }
  | { provider: "imap"; mode: "live"; credentials: ImapCredentials };

function isSecureLiveConfig(config: AdapterConfig | SecureAdapterConfig): config is Extract<SecureAdapterConfig, { mode: "live" }> {
  if (config.mode !== "live") return false;
  switch (config.provider) {
    case "gmail":
    case "outlook":
      return typeof config.credentials.refreshToken === "object";
    case "icloud":
    case "yahoo":
    case "imap":
      return typeof config.credentials.appPassword === "object";
  }
}

function createRuntimeAdapter(config: AdapterConfig, outlookRefreshTokenSink?: OutlookRefreshTokenSink): EmailAdapter {
  if (config.mode === "fixture") {
    const folderOverrides = config.fixtureFolderOverrides ?? {};
    config.fixtureFolderOverrides = folderOverrides;
    return buildDemoMailbox(config.provider, folderOverrides);
  }
  switch (config.provider) {
    case "gmail": return new GmailAdapter(config.credentials);
    case "outlook": return new OutlookAdapter(config.credentials, outlookRefreshTokenSink);
    case "icloud": return createIcloudAdapter(config.credentials.user, config.credentials.appPassword);
    case "yahoo": return createYahooAdapter(config.credentials.user, config.credentials.appPassword);
    case "imap": return createGenericImapAdapter(config.credentials);
  }
}

/**
 * Deferred adapter used only for secure session configuration. Credential
 * handles are resolved immediately before provider connect, then the raw
 * runtime adapter is discarded on disconnect. Outlook additionally writes a
 * replacement Microsoft refresh token back to the same secure handle before
 * the adapter treats that replacement as current.
 */
class SecureConfigAdapter implements EmailAdapter {
  readonly provider: Provider;
  private delegate: EmailAdapter | null = null;

  constructor(
    private readonly secureConfig: Extract<SecureAdapterConfig, { mode: "live" }>,
    private readonly credentialVault: CredentialVault,
  ) {
    this.provider = secureConfig.provider;
  }

  async connect(signal: AbortSignal): Promise<void> {
    if (this.delegate) throw new Error("Provider adapter is already connected.");
    const runtimeConfig = await materializeAdapterConfig(this.secureConfig, this.credentialVault);
    const outlookRotationSink: OutlookRefreshTokenSink | undefined =
      this.secureConfig.provider === "outlook"
        ? async (refreshToken) => {
            await replaceSecureOutlookRefreshToken(this.secureConfig, this.credentialVault, refreshToken);
          }
        : undefined;
    const delegate = createRuntimeAdapter(runtimeConfig, outlookRotationSink);
    try {
      await delegate.connect(signal);
      this.delegate = delegate;
    } catch (error) {
      await delegate.disconnect().catch(() => {});
      throw error;
    }
  }

  async listFolders(signal: AbortSignal): Promise<FolderDescriptor[]> {
    return this.connected().listFolders(signal);
  }

  async fetchPage(
    folder: FolderDescriptor,
    cursor: string | null,
    pageSize: number,
    signal: AbortSignal,
  ): Promise<FetchPage> {
    return this.connected().fetchPage(folder, cursor, pageSize, signal);
  }

  async moveToTrash(messageIds: string[], signal: AbortSignal): Promise<void> {
    return this.connected().moveToTrash(messageIds, signal);
  }

  async reportSpam(messageIds: string[], signal: AbortSignal): Promise<SpamReportResult> {
    return this.connected().reportSpam(messageIds, signal);
  }

  async disconnect(): Promise<void> {
    const delegate = this.delegate;
    this.delegate = null;
    if (delegate) await delegate.disconnect();
  }

  private connected(): EmailAdapter {
    if (!this.delegate) throw new Error("Not connected");
    return this.delegate;
  }
}

export function createAdapter(
  config: AdapterConfig | SecureAdapterConfig,
  credentialVault: CredentialVault = createCredentialVault(),
): EmailAdapter {
  if (config.mode === "fixture") return createRuntimeAdapter(config);
  if (isSecureLiveConfig(config)) return new SecureConfigAdapter(config, credentialVault);
  return createRuntimeAdapter(config);
}
