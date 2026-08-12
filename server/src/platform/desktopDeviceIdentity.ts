import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign,
  type KeyObject,
} from "node:crypto";
import type { CredentialReference, CredentialVault } from "../security/credentialVault.js";
import { dataBoundCredentialReference } from "../security/dataBoundEncryptionKey.js";
import type { AccountPlatformRuntime, DeviceIdentityPort } from "./accountFamilyPorts.js";
import { deriveDeviceId, type DevicePublicIdentity } from "./accountFamilyTypes.js";

const DEVICE_KEY_REFERENCE: CredentialReference = {
  kind: "local-encryption-key",
  id: "email-shield-device-identity-ed25519-v1",
};
const DEVICE_SECRET_VERSION = 1;

interface StoredDeviceKey {
  version: 1;
  algorithm: "ed25519";
  privateKeyPkcs8: string;
}

function parseStoredSecret(value: string): StoredDeviceKey {
  const parsed = JSON.parse(value) as Partial<StoredDeviceKey>;
  if (Object.keys(parsed).some((field) => !["version", "algorithm", "privateKeyPkcs8"].includes(field))) {
    throw new Error("Protected device identity contains unknown fields.");
  }
  if (parsed.version !== DEVICE_SECRET_VERSION || parsed.algorithm !== "ed25519" || typeof parsed.privateKeyPkcs8 !== "string") {
    throw new Error("Protected device identity format is invalid.");
  }
  const keyBytes = Buffer.from(parsed.privateKeyPkcs8, "base64");
  if (keyBytes.length < 32 || keyBytes.length > 512) throw new Error("Protected device private key is invalid.");
  createPrivateKey({ key: keyBytes, type: "pkcs8", format: "der" });
  return parsed as StoredDeviceKey;
}

abstract class Ed25519DeviceIdentityBase implements DeviceIdentityPort {
  protected abstract privateKey(): KeyObject;

  async currentPublicIdentity(): Promise<DevicePublicIdentity> {
    const publicKey = createPublicKey(this.privateKey()).export({ type: "spki", format: "der" }).toString("base64");
    return {
      algorithm: "ed25519",
      publicKeySpki: publicKey,
      platform: "desktop",
      label: "This desktop",
    };
  }

  async currentDeviceId(): Promise<string> {
    return deriveDeviceId(await this.currentPublicIdentity());
  }

  async signChallenge(challenge: string): Promise<string> {
    if (typeof challenge !== "string" || challenge.length < 16 || challenge.length > 4096) throw new Error("Device authentication challenge is invalid.");
    return sign(null, Buffer.from(challenge, "utf8"), this.privateKey()).toString("base64");
  }
}

export class DesktopDeviceIdentityProvider extends Ed25519DeviceIdentityBase {
  private readonly reference: CredentialReference;
  private stored: StoredDeviceKey | null = null;

  constructor(
    private readonly vault: CredentialVault,
    dataDirectory: string,
    platform: NodeJS.Platform = process.platform,
  ) {
    super();
    this.reference = dataBoundCredentialReference(DEVICE_KEY_REFERENCE, dataDirectory, platform);
  }

  async initialize(): Promise<void> {
    if (!this.vault.capabilities().available) throw new Error("A native credential vault is required for persistent Email Shield device identity.");
    const existing = await this.vault.read(this.reference);
    if (existing) {
      this.stored = parseStoredSecret(existing);
      return;
    }
    const pair = generateKeyPairSync("ed25519");
    const stored: StoredDeviceKey = {
      version: DEVICE_SECRET_VERSION,
      algorithm: "ed25519",
      privateKeyPkcs8: pair.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
    };
    await this.vault.write(this.reference, JSON.stringify(stored));
    const verified = await this.vault.read(this.reference);
    if (!verified) throw new Error("Protected Email Shield device identity could not be read after creation.");
    this.stored = parseStoredSecret(verified);
  }

  protected privateKey(): KeyObject {
    if (!this.stored) throw new Error("Desktop device identity has not been initialized.");
    return createPrivateKey({
      key: Buffer.from(this.stored.privateKeyPkcs8, "base64"),
      type: "pkcs8",
      format: "der",
    });
  }
}

/**
 * Used only when the platform has no usable native credential vault. The
 * account repository is also memory-only in that case, so restart truthfully
 * loses both identity and local account state rather than persisting a private
 * key in plaintext.
 */
export class EphemeralDesktopDeviceIdentityProvider extends Ed25519DeviceIdentityBase {
  private readonly key = generateKeyPairSync("ed25519").privateKey;

  async initialize(): Promise<void> {}

  protected privateKey(): KeyObject {
    return this.key;
  }
}

export class NodeAccountPlatformRuntime implements AccountPlatformRuntime {
  now(): number {
    return Date.now();
  }

  id(prefix: "acct" | "family" | "invite"): string {
    return `${prefix}_${randomUUID()}`;
  }

  secret(bytes = 24): string {
    if (!Number.isSafeInteger(bytes) || bytes < 16 || bytes > 64) throw new Error("Account secret size is invalid.");
    return randomBytes(bytes).toString("base64url");
  }
}
