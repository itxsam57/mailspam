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
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import type { SignedFeedEntry } from "../engine/layers/globalIntelligence.js";
import { readBoundedUtf8File } from "../util/localFileIntegrity.js";
import {
  MAX_COMMUNITY_DOMAIN_CHARS,
  MAX_COMMUNITY_FEED_ENTRIES,
  MAX_COMMUNITY_FEED_ENTRY_VALUE_CHARS,
  MAX_COMMUNITY_FEED_RESPONSE_BYTES,
  MAX_COMMUNITY_FEED_RULE_ID_CHARS,
  MAX_COMMUNITY_IDENTITY_ALIASES,
  MAX_COMMUNITY_IDENTITY_DOMAINS,
  MAX_COMMUNITY_IDENTITY_TEXT_CHARS,
  MAX_COMMUNITY_SIGNING_KEY_FILE_BYTES,
} from "./resourceLimits.js";
import type { CommunityFeedPayload, SignedCommunityFeed } from "./types.js";

const THREAT_ENTRY_TYPES = new Set([
  "sender",
  "domain",
  "url",
  "reply_to_domain",
  "url_domain",
  "attachment_hash",
  "campaign",
]);
const KEY_PAIR_INIT_WAIT_MS = 1_000;
const KEY_PAIR_INIT_POLL_MS = 10;
const KEY_PAIR_WAIT_STATE = new Int32Array(new SharedArrayBuffer(4));

export class CommunityFeedResourceLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CommunityFeedResourceLimitError";
  }
}

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

interface StoredSigningKeyPair {
  privatePem: string;
  publicPem: string;
}

function readStoredKeyPair(privatePath: string, publicPath: string): StoredSigningKeyPair {
  const pair = {
    privatePem: readBoundedUtf8File(privatePath, {
      description: "Community signing private key",
      maxBytes: MAX_COMMUNITY_SIGNING_KEY_FILE_BYTES,
      requireOwnerOnly: true,
    }),
    publicPem: readBoundedUtf8File(publicPath, {
      description: "Community signing public key",
      maxBytes: MAX_COMMUNITY_SIGNING_KEY_FILE_BYTES,
    }),
  };
  validateKeyPair(pair.privatePem, pair.publicPem);
  return pair;
}

function waitForStoredKeyPair(privatePath: string, publicPath: string): StoredSigningKeyPair {
  const deadline = Date.now() + KEY_PAIR_INIT_WAIT_MS;
  let observedInvalidPair = false;
  while (true) {
    if (existsSync(privatePath) && existsSync(publicPath)) {
      try {
        return readStoredKeyPair(privatePath, publicPath);
      } catch {
        observedInvalidPair = true;
      }
    }
    if (Date.now() >= deadline) break;
    Atomics.wait(KEY_PAIR_WAIT_STATE, 0, 0, KEY_PAIR_INIT_POLL_MS);
  }

  if (observedInvalidPair) {
    throw new Error("Community signing key storage is invalid; preserve the existing key files for diagnosis.");
  }
  throw new Error("Community signing key storage is incomplete; preserve the existing key file for diagnosis.");
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function onlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const accepted = new Set(allowed);
  return Object.keys(value).every((key) => accepted.has(key));
}

function boundedText(value: unknown, maxChars: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxChars;
}

function optionalFeedTimestamp(value: unknown): value is string | undefined {
  return value === undefined || (
    typeof value === "string" &&
    value.length <= 64 &&
    Number.isFinite(Date.parse(value))
  );
}

function validateThreatEntry(item: Record<string, unknown>): item is SignedFeedEntry & Record<string, unknown> {
  if (!onlyKeys(item, [
    "type", "value", "confirmedThreat", "ruleId", "independentReports", "firstSeen", "lastSeen",
  ])) return false;
  if (typeof item.type !== "string" || !THREAT_ENTRY_TYPES.has(item.type)) return false;
  if (!boundedText(item.value, MAX_COMMUNITY_FEED_ENTRY_VALUE_CHARS)) return false;
  if (typeof item.confirmedThreat !== "boolean") return false;
  if (!boundedText(item.ruleId, MAX_COMMUNITY_FEED_RULE_ID_CHARS)) return false;
  if (item.independentReports !== undefined && (
    !Number.isInteger(item.independentReports) ||
    (item.independentReports as number) < 1 ||
    (item.independentReports as number) > 1_000_000
  )) return false;
  if (!optionalFeedTimestamp(item.firstSeen) || !optionalFeedTimestamp(item.lastSeen)) return false;
  if (
    typeof item.firstSeen === "string" &&
    typeof item.lastSeen === "string" &&
    Date.parse(item.firstSeen) > Date.parse(item.lastSeen)
  ) return false;
  return true;
}

function validateIdentityEntry(item: Record<string, unknown>): item is SignedFeedEntry & Record<string, unknown> {
  if (!onlyKeys(item, ["type", "value", "aliases", "domains", "confirmedThreat", "ruleId"])) return false;
  if (item.type !== "identity" || item.confirmedThreat !== false) return false;
  if (!boundedText(item.value, MAX_COMMUNITY_IDENTITY_TEXT_CHARS)) return false;
  if (!boundedText(item.ruleId, MAX_COMMUNITY_FEED_RULE_ID_CHARS)) return false;
  if (!Array.isArray(item.aliases) || item.aliases.length > MAX_COMMUNITY_IDENTITY_ALIASES) return false;
  if (!item.aliases.every((alias) => boundedText(alias, MAX_COMMUNITY_IDENTITY_TEXT_CHARS))) return false;
  if (!Array.isArray(item.domains) || item.domains.length === 0 || item.domains.length > MAX_COMMUNITY_IDENTITY_DOMAINS) return false;
  if (!item.domains.every((domain) => boundedText(domain, MAX_COMMUNITY_DOMAIN_CHARS) && !/\s/.test(domain))) return false;
  return true;
}

function validateFeedEntry(value: unknown): value is SignedFeedEntry {
  const item = record(value);
  if (!item) return false;
  return item.type === "identity" ? validateIdentityEntry(item) : validateThreatEntry(item);
}

function validateFeedPayload(value: unknown): { payload: CommunityFeedPayload | null; reason: string | null } {
  const payload = record(value);
  if (!payload || !onlyKeys(payload, ["version", "generatedAt", "expiresAt", "entries"])) {
    return { payload: null, reason: "invalid_payload_shape" };
  }
  if (payload.version !== 1 || typeof payload.generatedAt !== "string" || typeof payload.expiresAt !== "string" || !Array.isArray(payload.entries)) {
    return { payload: null, reason: "invalid_payload_shape" };
  }
  if (payload.generatedAt.length > 64 || payload.expiresAt.length > 64) {
    return { payload: null, reason: "invalid_timestamps" };
  }
  if (payload.entries.length > MAX_COMMUNITY_FEED_ENTRIES) {
    return { payload: null, reason: "too_many_entries" };
  }
  if (!payload.entries.every(validateFeedEntry)) {
    return { payload: null, reason: "invalid_entry" };
  }
  return { payload: payload as unknown as CommunityFeedPayload, reason: null };
}

function documentWithinByteLimit(document: SignedCommunityFeed): boolean {
  try {
    return Buffer.byteLength(JSON.stringify(document), "utf8") <= MAX_COMMUNITY_FEED_RESPONSE_BYTES;
  } catch {
    return false;
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

    let selectedPair: StoredSigningKeyPair;
    if (configuredPrivatePem && configuredPublicPem) {
      validateKeyPair(configuredPrivatePem, configuredPublicPem);
      selectedPair = { privatePem: configuredPrivatePem, publicPem: configuredPublicPem };
    } else if (existsSync(privatePath) || existsSync(publicPath)) {
      selectedPair = waitForStoredKeyPair(privatePath, publicPath);
    } else {
      const pair = generateKeyPairSync("ed25519");
      const generatedPair = {
        privatePem: pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
        publicPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
      };
      try {
        writeFileSync(privatePath, generatedPair.privatePem, { mode: 0o600, flag: "wx" });
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        selectedPair = waitForStoredKeyPair(privatePath, publicPath);
        this.privatePem = selectedPair.privatePem;
        this.publicPem = selectedPair.publicPem;
        this.keyId = keyId(this.publicPem);
        return;
      }
      try {
        writeFileSync(publicPath, generatedPair.publicPem, { mode: 0o644, flag: "wx" });
      } catch (error) {
        throw new Error(
          `Community signing key initialization could not be completed; preserve the existing key files for diagnosis (${(error as NodeJS.ErrnoException).code ?? "unknown"}).`,
        );
      }
      try { chmodSync(privatePath, 0o600); } catch {}
      try { chmodSync(publicPath, 0o644); } catch {}
      selectedPair = generatedPair;
    }

    this.privatePem = selectedPair.privatePem;
    this.publicPem = selectedPair.publicPem;
    this.keyId = keyId(this.publicPem);
  }

  sign(payload: CommunityFeedPayload): SignedCommunityFeed {
    const validation = validateFeedPayload(payload);
    if (!validation.payload) {
      if (validation.reason === "too_many_entries") {
        throw new CommunityFeedResourceLimitError("Community feed exceeded the bounded entry-count limit.");
      }
      throw new Error(`Community feed payload is invalid (${validation.reason}).`);
    }
    const bytes = signingBytes(validation.payload);
    const signature = sign(null, bytes, createPrivateKey(this.privatePem));
    if (!verify(null, bytes, createPublicKey(this.publicPem), signature)) {
      throw new Error("Community feed could not be self-verified after signing.");
    }
    const document: SignedCommunityFeed = {
      version: 1,
      payload: structuredClone(validation.payload),
      signature: {
        algorithm: "Ed25519",
        keyId: this.keyId,
        value: signature.toString("base64"),
      },
    };
    if (!documentWithinByteLimit(document)) {
      throw new CommunityFeedResourceLimitError("Community feed exceeded the bounded signed-document size limit.");
    }
    return document;
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
  const root = record(document);
  if (!root || !onlyKeys(root, ["version", "payload", "signature"]) || root.version !== 1) {
    return { payload: null, reason: "unsupported_document_version" };
  }

  const payloadValidation = validateFeedPayload(root.payload);
  if (!payloadValidation.payload) return payloadValidation;
  const payload = payloadValidation.payload;
  const generatedAt = Date.parse(payload.generatedAt);
  const expiresAt = Date.parse(payload.expiresAt);
  if (!Number.isFinite(generatedAt) || !Number.isFinite(expiresAt)) return { payload: null, reason: "invalid_timestamps" };
  if (generatedAt > now.getTime() + 5 * 60_000) return { payload: null, reason: "generated_in_future" };
  if (expiresAt <= now.getTime()) return { payload: null, reason: "expired" };
  if (expiresAt <= generatedAt) return { payload: null, reason: "invalid_validity_window" };
  if (expiresAt - generatedAt > 48 * 60 * 60_000) return { payload: null, reason: "validity_window_too_long" };

  const signatureRecord = record(root.signature);
  if (!signatureRecord || !onlyKeys(signatureRecord, ["algorithm", "keyId", "value"])) {
    return { payload: null, reason: "invalid_signature_encoding" };
  }
  if (signatureRecord.algorithm !== "Ed25519") return { payload: null, reason: "unsupported_signature_algorithm" };
  if (typeof signatureRecord.keyId !== "string" || !/^[a-f0-9]{24}$/.test(signatureRecord.keyId)) {
    return { payload: null, reason: "invalid_key_id" };
  }
  if (typeof signatureRecord.value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(signatureRecord.value)) {
    return { payload: null, reason: "invalid_signature_encoding" };
  }

  let bytes: Buffer;
  let signature: Buffer;
  try {
    bytes = signingBytes(payload);
    signature = Buffer.from(signatureRecord.value, "base64");
  } catch {
    return { payload: null, reason: "serialization_failure" };
  }
  if (signature.length !== 64 || signature.toString("base64") !== signatureRecord.value) {
    return { payload: null, reason: "invalid_signature_encoding" };
  }
  if (!documentWithinByteLimit(document)) return { payload: null, reason: "document_too_large" };

  let matchingTrustedKey = false;
  for (const publicPem of trustedPublicKeys) {
    try {
      if (keyId(publicPem) !== signatureRecord.keyId) continue;
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
