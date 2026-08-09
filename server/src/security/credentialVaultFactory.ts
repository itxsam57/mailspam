import type { CredentialVault } from "./credentialVault.js";
import { UnsupportedCredentialVault } from "./credentialVault.js";
import { LinuxSecretServiceVault } from "./linuxSecretServiceVault.js";
import { MacOSKeychainVault } from "./macosKeychainVault.js";
import { WindowsCredentialManagerVault } from "./windowsCredentialManagerVault.js";

/**
 * Return only a real operating-system protected backend. There is intentionally
 * no plaintext, environment-variable or local-file fallback. A platform whose
 * native user-session service is absent reports unavailable and callers retain
 * the existing fail-closed / memory-only behavior.
 */
export function createCredentialVault(platform: NodeJS.Platform = process.platform): CredentialVault {
  if (platform === "win32") return new WindowsCredentialManagerVault();
  if (platform === "darwin") return new MacOSKeychainVault();
  if (platform === "linux") return new LinuxSecretServiceVault();
  return new UnsupportedCredentialVault(platform);
}
