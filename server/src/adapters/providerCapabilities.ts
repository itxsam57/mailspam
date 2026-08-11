import type { Provider } from "../canonical/envelope.js";

export const PROVIDER_CAPABILITY_SCHEMA_VERSION = 1 as const;

export type ProviderAuthentication = "oauth_pkce" | "app_password" | "server_credentials";

export interface ProviderCapabilityContract {
  schemaVersion: 1;
  provider: Provider;
  authentication: ProviderAuthentication;
  transport: "gmail_api" | "microsoft_graph" | "imap_tls";
  fixtureParity: true;
  capabilities: {
    connect: true;
    folderDiscovery: true;
    boundedPageFetch: true;
    quickScan: true;
    fullAudit: true;
    spamJunkScan: true;
    cancellation: true;
    moveToTrash: true;
    reportSpam: true;
    canonicalMime: true;
    sharedPortableCore: true;
  };
}

const REQUIRED_CAPABILITIES: ProviderCapabilityContract["capabilities"] = Object.freeze({
  connect: true,
  folderDiscovery: true,
  boundedPageFetch: true,
  quickScan: true,
  fullAudit: true,
  spamJunkScan: true,
  cancellation: true,
  moveToTrash: true,
  reportSpam: true,
  canonicalMime: true,
  sharedPortableCore: true,
});

function contract(
  provider: Provider,
  authentication: ProviderAuthentication,
  transport: ProviderCapabilityContract["transport"],
): ProviderCapabilityContract {
  return Object.freeze({
    schemaVersion: PROVIDER_CAPABILITY_SCHEMA_VERSION,
    provider,
    authentication,
    transport,
    fixtureParity: true,
    capabilities: REQUIRED_CAPABILITIES,
  });
}

/**
 * Versioned provider contract used by the release gate and UI. Differences are
 * confined to authentication and transport; every mailbox operation enters
 * the same canonical MIME and portable decision engine boundaries.
 */
export const PROVIDER_CAPABILITIES: Readonly<Record<Provider, ProviderCapabilityContract>> = Object.freeze({
  gmail: contract("gmail", "oauth_pkce", "gmail_api"),
  icloud: contract("icloud", "app_password", "imap_tls"),
  outlook: contract("outlook", "oauth_pkce", "microsoft_graph"),
  yahoo: contract("yahoo", "app_password", "imap_tls"),
  imap: contract("imap", "server_credentials", "imap_tls"),
});

export function providerCapabilitySnapshot(): ProviderCapabilityContract[] {
  return (["gmail", "icloud", "outlook", "yahoo", "imap"] as const)
    .map((provider) => ({
      ...PROVIDER_CAPABILITIES[provider],
      capabilities: { ...PROVIDER_CAPABILITIES[provider].capabilities },
    }));
}
