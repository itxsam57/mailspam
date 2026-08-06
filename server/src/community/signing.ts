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
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`).join(",")}}`;
}

function keyId(publicPem: string): string {
  const der = createPublicKey(publicPem).export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex").slice(0, 24);
}

export class CommunityFeedSigner {
  private readonly privatePem: string;
  readonly publicPem: string;
  readonly keyId: string;

  constructor(dataDirectory: string, configuredPrivatePem?: string, configuredPublicPem?: string) {
    mkdirSync(dataDirectory, { recursive: true, mode: 0o700 });
    const privatePath = join(dataDirectory, "community-feed-private.pem");
    const publicPath = join(dataDirectory, "community-feed-public.pem");

    if (configuredPrivatePem && configuredPublicPem) {
      this.privatePem = configuredPrivatePem;
      this.publicPem = configuredPublicPem;
    } else if (existsSync(privatePath) && existsSync(publicPath)) {
      this.privatePem = readFileSync(privatePath, "utf8");
      this.publicPem = readFileSync(publicPath, "utf8");
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
    const signature = sign(null, Buffer.from(canonicalize(payload), "utf8"), createPrivateKey(this.privatePem));
    return {
      version: 1,
      payload,
      signature: {
        algorithm: "Ed25519",
        keyId: this.keyId,
        value: signature.toString("base64"),
      },
    };
  }
}

export function verifyCommunityFeed(
  document: SignedCommunityFeed,
  trustedPublicKeys: string[],
  now = new Date(),
): CommunityFeedPayload | null {
  if (document.version !== 1 || document.signature?.algorithm !== "Ed25519") return null;
  const payload = document.payload;
  if (payload?.version !== 1 || !Array.isArray(payload.entries)) return null;
  const generatedAt = Date.parse(payload.generatedAt);
  const expiresAt = Date.parse(payload.expiresAt);
  if (!Number.isFinite(generatedAt) || !Number.isFinite(expiresAt)) return null;
  if (generatedAt > now.getTime() + 5 * 60_000 || expiresAt <= now.getTime()) return null;
  if (expiresAt - generatedAt > 48 * 60 * 60_000) return null;

  const message = Buffer.from(canonicalize(payload), "utf8");
  const signature = Buffer.from(document.signature.value, "base64");
  for (const publicPem of trustedPublicKeys) {
    try {
      if (keyId(publicPem) !== document.signature.keyId) continue;
      if (verify(null, message, createPublicKey(publicPem), signature)) return payload;
    } catch {}
  }
  return null;
}
