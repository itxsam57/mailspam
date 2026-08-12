import type { CredentialVault } from "./credentialVault.js";
import { UnsupportedCredentialVault } from "./credentialVault.js";
import { LinuxSecretServiceVault } from "./linuxSecretServiceVault.js";
import { MacOSKeychainVault } from "./macosKeychainVault.js";
import { WindowsCredentialManagerVault } from "./windowsCredentialManagerVault.js";

function createPlatformCredentialVault(platform: NodeJS.Platform): CredentialVault {
  if (platform === "win32") return new WindowsCredentialManagerVault();
  if (platform === "darwin") return new MacOSKeychainVault();
  if (platform === "linux") return new LinuxSecretServiceVault();
  return new UnsupportedCredentialVault(platform);
}

let runtimeCredentialVault: CredentialVault | null = null;

/**
 * The desktop runtime has one credential-custody boundary. Sharing the native
 * backend prevents repeated helper initialization across encrypted local
 * repositories and provider-session credentials.
 */
export function getRuntimeCredentialVault(): CredentialVault {
  runtimeCredentialVault ??= createPlatformCredentialVault(process.platform);
  return runtimeCredentialVault;
}

/**
 * With no explicit platform, return the process runtime vault. Supplying a
 * platform deliberately creates an isolated backend, which keeps unit tests,
 * migration probes and explicit callers independent from runtime state.
 * There is intentionally no plaintext, environment-variable or local-file
 * fallback.
 */
export function createCredentialVault(platform?: NodeJS.Platform): CredentialVault {
  return platform === undefined ? getRuntimeCredentialVault() : createPlatformCredentialVault(platform);
}
