import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import type { CommunityFeedPayload, SignedCommunityFeed } from "./types.js";

function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const serialized = JSON.stringify(value);
    if (serialized === undefined) throw new Error("Community feed contains an unsupported undefined value.");
    return serialized;
  }
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).filter((key) => record[key] !== undefined).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`).join(",")}}`;
}

function signingBytes(payload: CommunityFeedPayload): Buffer {
  return Buffer.from(canonicalize(payload), "utf8");
}

function keyId(publicPem: string): string {
  const der = createPublicKey(publicPem).export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex").slice(0, 24);
}

function validateKeyPair(privatePem: string, publicPem: string): void {
  const challenge = Buffer.from("email-shield-community-signing-key-validation-v1", "utf8");
  const signature = sign(null, challenge, createPrivateKey(privatePem));
  if (!verify(null, challenge, createPublicKey(publicPem), signature)) {
    throw new Error("Configured community signing private and public keys do not match.");
  }
}

export class CommunityFeedSigner {
  private readonly privatePem: string;
  readonly publicPem: string;
  readonly keyId: string;

  constructor(dataDirectory: string, configuredPrivatePem?: string, configuredPublicPem?: string) {
    mkdirSync(dataDirectory, { recursive: true, mode: 0o700 });
    const privatePath = join(dataDirectory, "community-feed-private.pem");
    const publicPath = join(dataDirectory, "community-feed-public.pem");

    if (Boolean(configuredPrivatePem) !== Boolean(configuredPublicPem)) {
      throw new Error("Community signing requires both the private and public key, or neither.");
    }

    if (configuredPrivatePem && configuredPublicPem) {
      validateKeyPair(configuredPrivatePem, configuredPublicPem);
      this.privatePem = configuredPrivatePem;
      this.publicPem = configuredPublicPem;
    } else if (existsSync(privatePath) && existsSync(publicPath)) {
      this.privatePem = readFileSync(privatePath, "utf8");
      this.publicPem = readFileSync(publicPath, "utf8");
      validateKeyPair(this.privatePem, this.publicPem);
    } else if (existsSync(privatePath) || existsSync(publicPath)) {
      throw new Error("Community signing key storage is incomplete; preserve the existing key file for diagnosis.");
    } else {
      const pair = generateKeyPairSync("ed25519");
      this.privatePem = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
      this.publicPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString();
      writeFileSync(privatePath, this.privatePem, { mode: 0o600, flag: "wx" });
      writeFileSync(publicPath, this.publicPem, { mode: 0o644, flag: "wx" });
      try { chmodSync(privatePath, 0o600); } catch {}
    }
    this.keyId = keyId(this.publicPem);
  }

  sign(payload: CommunityFeedPayload): SignedCommunityFeed {
    const bytes = signingBytes(payload);
    const signature = sign(null, bytes, createPrivateKey(this.privatePem));
    if (!verify(null, bytes, createPublicKey(this.publicPem), signature)) {
      throw new Error("Community feed could not be self-verified after signing.");
    }
    return {
      version: 1,
      payload: structuredClone(payload),
      signature: {
        algorithm: "Ed25519",
        keyId: this.keyId,
        value: signature.toString("base64"),
      },
    };
  }
}

export interface CommunityFeedVerificationResult {
  payload: CommunityFeedPayload | null;
  reason: string | null;
}

export function inspectCommunityFeed(
  document: SignedCommunityFeed,
  trustedPublicKeys: string[],
  now = new Date(),
): CommunityFeedVerificationResult {
  if (document.version !== 1) return { payload: null, reason: "unsupported_document_version" };
  if (document.signature?.algorithm !== "Ed25519") return { payload: null, reason: "unsupported_signature_algorithm" };
  const payload = document.payload;
  if (payload?.version !== 1 || !Array.isArray(payload.entries)) return { payload: null, reason: "invalid_payload_shape" };
  const generatedAt = Date.parse(payload.generatedAt);
  const expiresAt = Date.parse(payload.expiresAt);
  if (!Number.isFinite(generatedAt) || !Number.isFinite(expiresAt)) return { payload: null, reason: "invalid_timestamps" };
  if (generatedAt > now.getTime() + 5 * 60_000) return { payload: null, reason: "generated_in_future" };
  if (expiresAt <= now.getTime()) return { payload: null, reason: "expired" };
  if (expiresAt <= generatedAt) return { payload: null, reason: "invalid_validity_window" };
  if (expiresAt - generatedAt > 48 * 60 * 60_000) return { payload: null, reason: "validity_window_too_long" };
  if (!/^[a-f0-9]{24}$/.test(document.signature.keyId)) return { payload: null, reason: "invalid_key_id" };
  if (typeof document.signature.value !== "string" || document.signature.value.length < 40) {
    return { payload: null, reason: "invalid_signature_encoding" };
  }

  let bytes: Buffer;
  let signature: Buffer;
  try {
    bytes = signingBytes(payload);
    signature = Buffer.from(document.signature.value, "base64");
  } catch {
    return { payload: null, reason: "serialization_failure" };
  }

  let matchingTrustedKey = false;
  for (const publicPem of trustedPublicKeys) {
    try {
      if (keyId(publicPem) !== document.signature.keyId) continue;
      matchingTrustedKey = true;
      if (verify(null, bytes, createPublicKey(publicPem), signature)) {
        return { payload, reason: null };
      }
    } catch {}
  }
  return {
    payload: null,
    reason: matchingTrustedKey ? "signature_mismatch" : "untrusted_key",
  };
}

export function verifyCommunityFeed(
  document: SignedCommunityFeed,
  trustedPublicKeys: string[],
  now = new Date(),
): CommunityFeedPayload | null {
  return inspectCommunityFeed(document, trustedPublicKeys, now).payload;
}
