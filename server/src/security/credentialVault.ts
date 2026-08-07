import { createHash } from "node:crypto";

export type CredentialKind =
  | "oauth-refresh-token"
  | "oauth-client-secret"
  | "imap-app-password"
  | "local-encryption-key";

export interface CredentialReference {
  /**
   * Opaque, stable identifier owned by Email Shield. It must not contain a
   * mailbox address, provider token or any other secret value.
   */
  id: string;
  kind: CredentialKind;
}

export interface CredentialVaultCapabilities {
  backend: string;
  available: boolean;
  persistent: boolean;
  userBound: boolean;
  hardwareBacked: boolean;
  applicationBound: boolean;
}

export interface CredentialVault {
  capabilities(): CredentialVaultCapabilities;
  write(reference: CredentialReference, secret: string): Promise<void>;
  read(reference: CredentialReference): Promise<string | null>;
  delete(reference: CredentialReference): Promise<void>;
}

export type CredentialVaultErrorCode =
  | "VAULT_UNAVAILABLE"
  | "INVALID_REFERENCE"
  | "INVALID_SECRET"
  | "VAULT_OPERATION_FAILED";

export class CredentialVaultError extends Error {
  constructor(
    readonly code: CredentialVaultErrorCode,
    message: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "CredentialVaultError";
  }
}

const REFERENCE_ID_PATTERN = /^[A-Za-z0-9._:-]{8,160}$/;
const TARGET_NAMESPACE = "email-shield-credential-v1\0";

export function validateCredentialReference(reference: CredentialReference): void {
  if (!reference || typeof reference !== "object") {
    throw new CredentialVaultError("INVALID_REFERENCE", "Credential reference is required.");
  }
  if (!REFERENCE_ID_PATTERN.test(reference.id)) {
    throw new CredentialVaultError(
      "INVALID_REFERENCE",
      "Credential reference ID must be an opaque Email Shield identifier.",
    );
  }
  if (![
    "oauth-refresh-token",
    "oauth-client-secret",
    "imap-app-password",
    "local-encryption-key",
  ].includes(reference.kind)) {
    throw new CredentialVaultError("INVALID_REFERENCE", "Credential reference kind is unsupported.");
  }
}

/**
 * Windows Credential Manager target names are visible metadata to the signed-in
 * operating-system user. Hash the internal reference so mailbox/provider
 * identity never has to appear in the target name itself.
 */
export function credentialTargetName(reference: CredentialReference): string {
  validateCredentialReference(reference);
  const digest = createHash("sha256")
    .update(TARGET_NAMESPACE, "utf8")
    .update(reference.kind, "utf8")
    .update("\0", "utf8")
    .update(reference.id, "utf8")
    .digest("hex");
  return `EmailShield/${digest}`;
}

export function validateCredentialSecret(secret: string): void {
  if (typeof secret !== "string" || secret.length === 0) {
    throw new CredentialVaultError("INVALID_SECRET", "Credential secret must not be empty.");
  }
  if (Buffer.byteLength(secret, "utf8") > 2_560) {
    // Windows CRED_MAX_CREDENTIAL_BLOB_SIZE is 5 * 512 bytes. Keeping the
    // shared contract within that limit guarantees cross-call consistency for
    // the first production backend instead of truncating or silently changing
    // a secret.
    throw new CredentialVaultError("INVALID_SECRET", "Credential secret exceeds the supported secure-vault size.");
  }
}

export class UnsupportedCredentialVault implements CredentialVault {
  constructor(private readonly platform: string) {}

  capabilities(): CredentialVaultCapabilities {
    return {
      backend: `unsupported:${this.platform}`,
      available: false,
      persistent: false,
      userBound: false,
      hardwareBacked: false,
      applicationBound: false,
    };
  }

  async write(_reference: CredentialReference, _secret: string): Promise<void> {
    throw this.unavailable();
  }

  async read(_reference: CredentialReference): Promise<string | null> {
    throw this.unavailable();
  }

  async delete(_reference: CredentialReference): Promise<void> {
    throw this.unavailable();
  }

  private unavailable(): CredentialVaultError {
    return new CredentialVaultError(
      "VAULT_UNAVAILABLE",
      `A protected operating-system credential vault is not implemented for ${this.platform}.`,
    );
  }
}
