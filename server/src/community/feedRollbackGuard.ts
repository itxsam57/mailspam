import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { readBoundedRegularFile, readBoundedUtf8File, replaceFileFromTemporaryPath } from "../util/localFileIntegrity.js";
import { communityFeedPayloadDigest } from "./signing.js";
import type { CommunityFeedPayload, SignedCommunityFeed } from "./types.js";

const ALGORITHM = "aes-256-gcm";
const AAD = Buffer.from("email-shield-community-feed-rollback-state-v1", "utf8");
const KEY_BYTES = 32;
const MAX_STATE_BYTES = 8 * 1024;
const MAX_ACCEPTED_KEYS = 4;
const KEY_ID_PATTERN = /^[a-f0-9]{24}$/;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/;

interface RollbackCheckpoint {
  version: 1;
  generatedAt: string;
  payloadDigest: string;
  keyIds: string[];
}

interface EncryptedCheckpoint {
  version: 1;
  algorithm: "aes-256-gcm";
  iv: string;
  authTag: string;
  ciphertext: string;
}

function validateCheckpoint(value: unknown): RollbackCheckpoint {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Community feed rollback checkpoint is invalid.");
  const item = value as Record<string, unknown>;
  if (Object.keys(item).some((key) => !["version", "generatedAt", "payloadDigest", "keyIds"].includes(key))) {
    throw new Error("Community feed rollback checkpoint is invalid.");
  }
  if (item.version !== 1 || typeof item.generatedAt !== "string" || item.generatedAt.length > 64) {
    throw new Error("Community feed rollback checkpoint is invalid.");
  }
  const timestamp = Date.parse(item.generatedAt);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== item.generatedAt) {
    throw new Error("Community feed rollback checkpoint is invalid.");
  }
  if (typeof item.payloadDigest !== "string" || !DIGEST_PATTERN.test(item.payloadDigest)) {
    throw new Error("Community feed rollback checkpoint is invalid.");
  }
  const keyIds = item.keyIds;
  if (!Array.isArray(keyIds) || keyIds.length === 0 || keyIds.length > MAX_ACCEPTED_KEYS ||
      keyIds.some((key, index) => typeof key !== "string" || !KEY_ID_PATTERN.test(key) || keyIds.indexOf(key) !== index)) {
    throw new Error("Community feed rollback checkpoint is invalid.");
  }
  return item as unknown as RollbackCheckpoint;
}

/**
 * Persists only signed-feed ordering metadata. No report, mailbox, indicator,
 * rule or message content enters this state.
 */
export class CommunityFeedRollbackGuard {
  private readonly keyPath: string;
  private readonly statePath: string;
  private keyCache: Buffer | null = null;
  private checkpointCache: RollbackCheckpoint | null | undefined;

  constructor(private readonly dataDirectory: string) {
    this.keyPath = join(dataDirectory, "community-feed-rollback.key");
    this.statePath = join(dataDirectory, "community-feed-rollback.enc.json");
  }

  accept(document: SignedCommunityFeed, payload: CommunityFeedPayload): void {
    const keyId = document.signature.keyId;
    if (!KEY_ID_PATTERN.test(keyId)) throw new Error("Community feed rollback guard received an invalid signing key identity.");
    const generatedAtMs = Date.parse(payload.generatedAt);
    if (!Number.isFinite(generatedAtMs)) throw new Error("Community feed rollback guard received an invalid generation timestamp.");
    const digest = communityFeedPayloadDigest(payload);
    const previous = this.readCheckpoint();

    if (previous) {
      const previousAtMs = Date.parse(previous.generatedAt);
      if (generatedAtMs < previousAtMs) {
        throw new Error("Community feed rollback was rejected because its generation is older than the accepted checkpoint.");
      }
      if (generatedAtMs === previousAtMs && digest !== previous.payloadDigest) {
        throw new Error("Community feed equivocation was rejected at the accepted generation timestamp.");
      }
    }

    const keyIds = previous && generatedAtMs === Date.parse(previous.generatedAt)
      ? [...new Set([...previous.keyIds, keyId])].slice(-MAX_ACCEPTED_KEYS)
      : [keyId];
    const next: RollbackCheckpoint = {
      version: 1,
      generatedAt: payload.generatedAt,
      payloadDigest: digest,
      keyIds,
    };
    if (previous && JSON.stringify(previous) === JSON.stringify(next)) return;
    this.writeCheckpoint(next);
    this.checkpointCache = next;
  }

  private ensureDirectory(): void {
    mkdirSync(this.dataDirectory, { recursive: true, mode: 0o700 });
    try { chmodSync(this.dataDirectory, 0o700); } catch {}
  }

  private readKey(): Buffer {
    if (this.keyCache) return this.keyCache;
    this.ensureDirectory();
    if (!existsSync(this.keyPath)) {
      const generated = randomBytes(KEY_BYTES);
      try { writeFileSync(this.keyPath, generated, { flag: "wx", mode: 0o600 }); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
      finally { generated.fill(0); }
    }
    this.keyCache = readBoundedRegularFile(this.keyPath, {
      description: "Community feed rollback key",
      exactBytes: KEY_BYTES,
      maxBytes: KEY_BYTES,
      requireOwnerOnly: true,
    });
    try { chmodSync(this.keyPath, 0o600); } catch {}
    return this.keyCache;
  }

  private readCheckpoint(): RollbackCheckpoint | null {
    if (this.checkpointCache !== undefined) return this.checkpointCache;
    if (!existsSync(this.statePath)) {
      this.checkpointCache = null;
      return null;
    }
    try {
      const envelope = JSON.parse(readBoundedUtf8File(this.statePath, {
        description: "Encrypted community feed rollback checkpoint",
        maxBytes: MAX_STATE_BYTES,
        requireOwnerOnly: true,
      })) as EncryptedCheckpoint;
      if (envelope.version !== 1 || envelope.algorithm !== ALGORITHM) throw new Error("Unsupported checkpoint format.");
      const decipher = createDecipheriv(ALGORITHM, this.readKey(), Buffer.from(envelope.iv, "base64"));
      decipher.setAAD(AAD);
      decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, "base64")),
        decipher.final(),
      ]).toString("utf8");
      this.checkpointCache = validateCheckpoint(JSON.parse(plaintext));
      return this.checkpointCache;
    } catch (error) {
      throw new Error(`Community feed rollback checkpoint could not be read: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private writeCheckpoint(checkpoint: RollbackCheckpoint): void {
    this.ensureDirectory();
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGORITHM, this.readKey(), iv);
    cipher.setAAD(AAD);
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(checkpoint), "utf8"), cipher.final()]);
    const envelope: EncryptedCheckpoint = {
      version: 1,
      algorithm: ALGORITHM,
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
    const serialized = JSON.stringify(envelope);
    if (Buffer.byteLength(serialized, "utf8") > MAX_STATE_BYTES) throw new Error("Community feed rollback checkpoint exceeds its storage limit.");
    const temporaryPath = `${this.statePath}.${process.pid}.${randomBytes(5).toString("hex")}.tmp`;
    writeFileSync(temporaryPath, serialized, { mode: 0o600 });
    replaceFileFromTemporaryPath(temporaryPath, this.statePath);
    try { chmodSync(this.statePath, 0o600); } catch {}
  }
}
