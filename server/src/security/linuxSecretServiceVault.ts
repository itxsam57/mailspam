import { existsSync } from "node:fs";
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

export interface LinuxSecretServiceBridgeRequest {
  operation: "write" | "read" | "delete";
  target: string;
  secret?: string;
}

export interface LinuxSecretServiceBridgeResponse {
  ok: boolean;
  found?: boolean;
  secret?: string;
}

export interface LinuxSecretServiceBridge {
  invoke(request: LinuxSecretServiceBridgeRequest): Promise<LinuxSecretServiceBridgeResponse>;
}

const SECRET_TOOL_PATH = "/usr/bin/secret-tool";
const APPLICATION_ATTRIBUTE = "email-shield-v1";
const LABEL = "Email Shield protected credential";

function lookupArgs(target: string): string[] {
  return ["lookup", "application", APPLICATION_ATTRIBUTE, "credential", target];
}

function clearArgs(target: string): string[] {
  return ["clear", "application", APPLICATION_ATTRIBUTE, "credential", target];
}

export class SecretToolLinuxCredentialBridge implements LinuxSecretServiceBridge {
  async invoke(request: LinuxSecretServiceBridgeRequest): Promise<LinuxSecretServiceBridgeResponse> {
    if (process.platform !== "linux" || !existsSync(SECRET_TOOL_PATH)) {
      throw new CredentialVaultError("VAULT_UNAVAILABLE", "Linux Secret Service is unavailable on this platform.");
    }

    if (request.operation === "write") {
      if (typeof request.secret !== "string" || !request.secret) {
        throw new CredentialVaultError("INVALID_SECRET", "Credential secret must not be empty.");
      }
      const result = await runNativeCredentialCommand({
        executable: SECRET_TOOL_PATH,
        args: [
          "store",
          `--label=${LABEL}`,
          "application", APPLICATION_ATTRIBUTE,
          "credential", request.target,
        ],
        // secret-tool explicitly supports receiving the complete secret on
        // stdin until EOF. Do not append a newline; it would become secret data.
        stdin: request.secret,
        backendLabel: "Linux Secret Service",
      });
      if (result.exitCode !== 0) {
        throw new CredentialVaultError("VAULT_OPERATION_FAILED", "Linux Secret Service write failed.");
      }
      return { ok: true };
    }

    if (request.operation === "read") {
      const result = await runNativeCredentialCommand({
        executable: SECRET_TOOL_PATH,
        args: lookupArgs(request.target),
        backendLabel: "Linux Secret Service",
      });
      // secret-tool returns no secret and a non-zero status when no unlocked
      // matching item exists. Other failures also remain fail-closed at callers:
      // writes/deletes require success and existing encrypted policy databases
      // refuse to generate a replacement key when read returns null.
      if (result.exitCode !== 0 && result.stdout.length === 0) return { ok: true, found: false };
      if (result.exitCode !== 0) {
        throw new CredentialVaultError("VAULT_OPERATION_FAILED", "Linux Secret Service read failed.");
      }
      const secret = result.stdout.toString("utf8");
      if (!secret) return { ok: true, found: false };
      validateCredentialSecret(secret);
      return { ok: true, found: true, secret };
    }

    const result = await runNativeCredentialCommand({
      executable: SECRET_TOOL_PATH,
      args: clearArgs(request.target),
      backendLabel: "Linux Secret Service",
    });
    if (result.exitCode !== 0) {
      throw new CredentialVaultError("VAULT_OPERATION_FAILED", "Linux Secret Service deletion failed.");
    }
    return { ok: true };
  }
}

export class LinuxSecretServiceVault implements CredentialVault {
  constructor(private readonly bridge: LinuxSecretServiceBridge = new SecretToolLinuxCredentialBridge()) {}

  capabilities(): CredentialVaultCapabilities {
    const nativeAvailable = process.platform === "linux"
      && existsSync(SECRET_TOOL_PATH)
      && Boolean(process.env.DBUS_SESSION_BUS_ADDRESS?.trim());
    return {
      backend: "linux-secret-service",
      available: nativeAvailable || !(this.bridge instanceof SecretToolLinuxCredentialBridge),
      persistent: true,
      userBound: true,
      hardwareBacked: false,
      applicationBound: false,
    };
  }

  async write(reference: CredentialReference, secret: string): Promise<void> {
    validateCredentialReference(reference);
    validateCredentialSecret(secret);
    if (!this.capabilities().available) {
      throw new CredentialVaultError("VAULT_UNAVAILABLE", "Linux Secret Service is unavailable in this user session.");
    }
    try {
      const response = await this.bridge.invoke({ operation: "write", target: credentialTargetName(reference), secret });
      if (!response.ok) throw new Error("Credential write was not confirmed.");
    } catch (error) {
      if (error instanceof CredentialVaultError) throw error;
      throw new CredentialVaultError("VAULT_OPERATION_FAILED", "Linux Secret Service write failed.");
    }
  }

  async read(reference: CredentialReference): Promise<string | null> {
    validateCredentialReference(reference);
    if (!this.capabilities().available) {
      throw new CredentialVaultError("VAULT_UNAVAILABLE", "Linux Secret Service is unavailable in this user session.");
    }
    try {
      const response = await this.bridge.invoke({ operation: "read", target: credentialTargetName(reference) });
      if (!response.ok) throw new Error("Credential read was not confirmed.");
      if (!response.found) return null;
      if (typeof response.secret !== "string" || !response.secret) {
        throw new Error("Secret Service returned an invalid credential payload.");
      }
      validateCredentialSecret(response.secret);
      return response.secret;
    } catch (error) {
      if (error instanceof CredentialVaultError) throw error;
      throw new CredentialVaultError("VAULT_OPERATION_FAILED", "Linux Secret Service read failed.");
    }
  }

  async delete(reference: CredentialReference): Promise<void> {
    validateCredentialReference(reference);
    if (!this.capabilities().available) {
      throw new CredentialVaultError("VAULT_UNAVAILABLE", "Linux Secret Service is unavailable in this user session.");
    }
    try {
      const response = await this.bridge.invoke({ operation: "delete", target: credentialTargetName(reference) });
      if (!response.ok) throw new Error("Credential deletion was not confirmed.");
    } catch (error) {
      if (error instanceof CredentialVaultError) throw error;
      throw new CredentialVaultError("VAULT_OPERATION_FAILED", "Linux Secret Service deletion failed.");
    }
  }
}
