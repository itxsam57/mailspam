import type { CredentialVault } from "./credentialVault.js";
import { UnsupportedCredentialVault } from "./credentialVault.js";
import { WindowsCredentialManagerVault } from "./windowsCredentialManagerVault.js";

/**
 * Returns only a real operating-system protected backend. There is
 * intentionally no plaintext, environment-variable or local-file fallback:
 * unsupported platforms fail closed until their native vault is implemented.
 */
export function createCredentialVault(platform: NodeJS.Platform = process.platform): CredentialVault {
  if (platform === "win32") return new WindowsCredentialManagerVault();
  return new UnsupportedCredentialVault(platform);
}
