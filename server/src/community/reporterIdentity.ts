import { createHmac, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { readBoundedRegularFile } from "../util/localFileIntegrity.js";

/**
 * Creates a stable pseudonym for one mailbox on one Email Shield installation.
 * The account key is never transmitted. A fresh installation uses a new random
 * HMAC key, so community operators cannot reverse or directly correlate the
 * reporter proof to a mailbox address.
 */
export class CommunityReporterIdentity {
  private readonly keyPath: string;
  private keyCache: Buffer | null = null;

  constructor(private readonly dataDirectory: string) {
    this.keyPath = join(dataDirectory, "community-reporter.key");
  }

  proofForAccount(accountKey: string): string {
    if (!/^[a-f0-9]{64}$/.test(accountKey)) throw new Error("Community reporter account key is invalid.");
    return createHmac("sha256", this.readKey())
      .update("email-shield-community-reporter-v1\0", "utf8")
      .update(accountKey, "utf8")
      .digest("hex");
  }

  private readKey(): Buffer {
    if (this.keyCache) return this.keyCache;
    mkdirSync(this.dataDirectory, { recursive: true, mode: 0o700 });
    if (!existsSync(this.keyPath)) {
      const key = randomBytes(32);
      try { writeFileSync(this.keyPath, key, { mode: 0o600, flag: "wx" }); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      } finally {
        key.fill(0);
      }
    }
    let key: Buffer;
    try {
      key = readBoundedRegularFile(this.keyPath, {
        description: "Community reporter identity key",
        maxBytes: 32,
        exactBytes: 32,
        requireOwnerOnly: true,
      });
    } catch {
      throw new Error("Community reporter identity key is invalid.");
    }
    try { chmodSync(this.keyPath, 0o600); } catch {}
    this.keyCache = key;
    return key;
  }
}
