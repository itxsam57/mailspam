import {
  CredentialVaultError,
  credentialTargetName,
  type CredentialReference,
  type CredentialVault,
  type CredentialVaultCapabilities,
  validateCredentialReference,
  validateCredentialSecret,
} from "./credentialVault.js";
import { runNativeCredentialCommand } from "./nativeCredentialCommand.js";

export interface MacOSKeychainBridgeRequest {
  operation: "write" | "read" | "delete";
  target: string;
  secret?: string;
}

export interface MacOSKeychainBridgeResponse {
  ok: boolean;
  found?: boolean;
  secret?: string;
}

export interface MacOSKeychainBridge {
  invoke(request: MacOSKeychainBridgeRequest): Promise<MacOSKeychainBridgeResponse>;
}

const SECURITY_PATH = "/usr/bin/security";
const SERVICE = "EmailShieldCredentialV1";
const NOT_FOUND_EXIT_CODE = 44; // errSecItemNotFound (-25300) modulo POSIX exit status.

function encodeSecret(secret: string): string {
  return Buffer.from(secret, "utf8").toString("base64");
}

function decodeSecret(encoded: string): string {
  const normalized = encoded.replace(/\r?\n$/, "");
  const bytes = Buffer.from(normalized, "base64");
  if (!normalized || bytes.toString("base64") !== normalized) {
    throw new CredentialVaultError("VAULT_OPERATION_FAILED", "macOS Keychain returned an invalid credential payload.");
  }
  const secret = bytes.toString("utf8");
  validateCredentialSecret(secret);
  return secret;
}

export class SecurityCliMacOSKeychainBridge implements MacOSKeychainBridge {
  async invoke(request: MacOSKeychainBridgeRequest): Promise<MacOSKeychainBridgeResponse> {
    if (process.platform !== "darwin") {
      throw new CredentialVaultError("VAULT_UNAVAILABLE", "macOS Keychain is unavailable on this platform.");
    }

    if (request.operation === "write") {
      if (typeof request.secret !== "string" || !request.secret) {
        throw new CredentialVaultError("INVALID_SECRET", "Credential secret must not be empty.");
      }
      const encoded = encodeSecret(request.secret);
      const result = await runNativeCredentialCommand({
        executable: SECURITY_PATH,
        args: [
          "add-generic-password",
          "-a", request.target,
          "-s", SERVICE,
          "-D", "Email Shield protected credential",
          "-U",
          // Keep -w last so /usr/bin/security reads the password from its
          // prompt input rather than from the process command line.
          "-w",
        ],
        stdin: `${encoded}\n`,
        backendLabel: "macOS Keychain",
      });
      if (result.exitCode !== 0) {
        throw new CredentialVaultError("VAULT_OPERATION_FAILED", "macOS Keychain write failed.");
      }
      return { ok: true };
    }

    if (request.operation === "read") {
      const result = await runNativeCredentialCommand({
        executable: SECURITY_PATH,
        args: ["find-generic-password", "-a", request.target, "-s", SERVICE, "-w"],
        backendLabel: "macOS Keychain",
      });
      if (result.exitCode === NOT_FOUND_EXIT_CODE) return { ok: true, found: false };
      if (result.exitCode !== 0) {
        throw new CredentialVaultError("VAULT_OPERATION_FAILED", "macOS Keychain read failed.");
      }
      return { ok: true, found: true, secret: decodeSecret(result.stdout.toString("utf8")) };
    }

    const result = await runNativeCredentialCommand({
      executable: SECURITY_PATH,
      args: ["delete-generic-password", "-a", request.target, "-s", SERVICE],
      backendLabel: "macOS Keychain",
    });
    if (result.exitCode !== 0 && result.exitCode !== NOT_FOUND_EXIT_CODE) {
      throw new CredentialVaultError("VAULT_OPERATION_FAILED", "macOS Keychain deletion failed.");
    }
    return { ok: true };
  }
}

export class MacOSKeychainVault implements CredentialVault {
  constructor(private readonly bridge: MacOSKeychainBridge = new SecurityCliMacOSKeychainBridge()) {}

  capabilities(): CredentialVaultCapabilities {
    return {
      backend: "macos-keychain",
      available: process.platform === "darwin" || !(this.bridge instanceof SecurityCliMacOSKeychainBridge),
      persistent: true,
      userBound: true,
      hardwareBacked: false,
      applicationBound: false,
    };
  }

  async write(reference: CredentialReference, secret: string): Promise<void> {
    validateCredentialReference(reference);
    validateCredentialSecret(secret);
    try {
      const response = await this.bridge.invoke({
        operation: "write",
        target: credentialTargetName(reference),
        secret,
      });
      if (!response.ok) throw new Error("Credential write was not confirmed.");
    } catch (error) {
      if (error instanceof CredentialVaultError) throw error;
      throw new CredentialVaultError("VAULT_OPERATION_FAILED", "macOS Keychain write failed.");
    }
  }

  async read(reference: CredentialReference): Promise<string | null> {
    validateCredentialReference(reference);
    try {
      const response = await this.bridge.invoke({ operation: "read", target: credentialTargetName(reference) });
      if (!response.ok) throw new Error("Credential read was not confirmed.");
      if (!response.found) return null;
      if (typeof response.secret !== "string" || !response.secret) {
        throw new Error("Keychain returned an invalid credential payload.");
      }
      validateCredentialSecret(response.secret);
      return response.secret;
    } catch (error) {
      if (error instanceof CredentialVaultError) throw error;
      throw new CredentialVaultError("VAULT_OPERATION_FAILED", "macOS Keychain read failed.");
    }
  }

  async delete(reference: CredentialReference): Promise<void> {
    validateCredentialReference(reference);
    try {
      const response = await this.bridge.invoke({ operation: "delete", target: credentialTargetName(reference) });
      if (!response.ok) throw new Error("Credential deletion was not confirmed.");
    } catch (error) {
      if (error instanceof CredentialVaultError) throw error;
      throw new CredentialVaultError("VAULT_OPERATION_FAILED", "macOS Keychain deletion failed.");
    }
  }
}
