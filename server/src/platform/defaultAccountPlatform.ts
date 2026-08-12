import type { CredentialVault } from "../security/credentialVault.js";
import { getRuntimeCredentialVault } from "../security/credentialVaultFactory.js";
import { defaultEmailShieldDataDirectory } from "../security/dataDirectory.js";
import { AccountPlatformService } from "./accountFamilyService.js";
import { createDefaultAccountPlatformRepository } from "./accountFamilyPersistence.js";
import {
  DesktopDeviceIdentityProvider,
  EphemeralDesktopDeviceIdentityProvider,
  NodeAccountPlatformRuntime,
} from "./desktopDeviceIdentity.js";

export type DefaultDesktopDeviceIdentity = DesktopDeviceIdentityProvider | EphemeralDesktopDeviceIdentityProvider;

let service: AccountPlatformService | null = null;
let deviceIdentity: DefaultDesktopDeviceIdentity | null = null;

export async function initializeDefaultAccountPlatform(options: {
  credentialVault?: CredentialVault;
  dataDirectory?: string;
  platform?: NodeJS.Platform;
} = {}): Promise<void> {
  if (service && deviceIdentity) return;
  const platform = options.platform ?? process.platform;
  const dataDirectory = options.dataDirectory ?? defaultEmailShieldDataDirectory();
  const vault = options.credentialVault ?? getRuntimeCredentialVault();
  const repository = await createDefaultAccountPlatformRepository({
    dataDirectory,
    credentialVault: vault,
    platform,
  });
  const identity = vault.capabilities().available
    ? new DesktopDeviceIdentityProvider(vault, dataDirectory, platform)
    : new EphemeralDesktopDeviceIdentityProvider();
  await identity.initialize();
  service = new AccountPlatformService(repository, new NodeAccountPlatformRuntime());
  deviceIdentity = identity;
}

export function getAccountPlatformService(): AccountPlatformService {
  if (!service) throw new Error("Email Shield account platform has not been initialized.");
  return service;
}

export function getDesktopDeviceIdentity(): DefaultDesktopDeviceIdentity {
  if (!deviceIdentity) throw new Error("Email Shield desktop device identity has not been initialized.");
  return deviceIdentity;
}
