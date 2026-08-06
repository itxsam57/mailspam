import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import type { CommunityReportSubmission } from "./types.js";

const ALGORITHM = "aes-256-gcm";
const AAD = Buffer.from("email-shield-community-outbox-v1", "utf8");
const MAX_PENDING_REPORTS = 2_000;

interface OutboxDatabase {
  version: 1;
  pending: CommunityReportSubmission[];
}

interface EncryptedEnvelope {
  version: 1;
  algorithm: "aes-256-gcm";
  iv: string;
  authTag: string;
  ciphertext: string;
}

export class EncryptedCommunityOutbox {
  private readonly keyPath: string;
  private readonly outboxPath: string;
  private keyCache: Buffer | null = null;

  constructor(private readonly dataDirectory: string) {
    this.keyPath = join(dataDirectory, "community-storage.key");
    this.outboxPath = join(dataDirectory, "community-outbox.enc.json");
  }

  enqueue(report: CommunityReportSubmission): void {
    const database = this.read();
    const key = `${report.reporterProof}\0${report.campaignFingerprint}`;
    const existingIndex = database.pending.findIndex(
      (item) => `${item.reporterProof}\0${item.campaignFingerprint}` === key,
    );
    if (existingIndex >= 0) database.pending[existingIndex] = report;
    else database.pending.push(report);
    if (database.pending.length > MAX_PENDING_REPORTS) database.pending.splice(0, database.pending.length - MAX_PENDING_REPORTS);
    this.write(database);
  }

  list(): CommunityReportSubmission[] {
    return this.read().pending.map((item) => structuredClone(item));
  }

  remove(reporterProof: string, campaignFingerprint: string): void {
    const database = this.read();
    const remaining = database.pending.filter(
      (item) => item.reporterProof !== reporterProof || item.campaignFingerprint !== campaignFingerprint,
    );
    if (remaining.length === database.pending.length) return;
    database.pending = remaining;
    this.write(database);
  }

  count(): number {
    return this.read().pending.length;
  }

  private readKey(): Buffer {
    if (this.keyCache) return this.keyCache;
    mkdirSync(this.dataDirectory, { recursive: true, mode: 0o700 });
    if (!existsSync(this.keyPath)) {
      const key = randomBytes(32);
      try { writeFileSync(this.keyPath, key, { mode: 0o600, flag: "wx" }); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }
    }
    const key = readFileSync(this.keyPath);
    if (key.length !== 32) throw new Error("Community outbox encryption key is invalid.");
    try { chmodSync(this.keyPath, 0o600); } catch {}
    this.keyCache = key;
    return key;
  }

  private read(): OutboxDatabase {
    if (!existsSync(this.outboxPath)) return { version: 1, pending: [] };
    try {
      const envelope = JSON.parse(readFileSync(this.outboxPath, "utf8")) as EncryptedEnvelope;
      if (envelope.version !== 1 || envelope.algorithm !== ALGORITHM) throw new Error("Unsupported format.");
      const decipher = createDecipheriv(ALGORITHM, this.readKey(), Buffer.from(envelope.iv, "base64"));
      decipher.setAAD(AAD);
      decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, "base64")),
        decipher.final(),
      ]).toString("utf8");
      const parsed = JSON.parse(plaintext) as OutboxDatabase;
      if (parsed.version !== 1 || !Array.isArray(parsed.pending)) throw new Error("Invalid database.");
      return parsed;
    } catch (error) {
      throw new Error(`Encrypted community outbox could not be read: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private write(database: OutboxDatabase): void {
    mkdirSync(this.dataDirectory, { recursive: true, mode: 0o700 });
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGORITHM, this.readKey(), iv);
    cipher.setAAD(AAD);
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(database), "utf8"), cipher.final()]);
    const envelope: EncryptedEnvelope = {
      version: 1,
      algorithm: ALGORITHM,
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
    const temporaryPath = `${this.outboxPath}.${process.pid}.${randomBytes(5).toString("hex")}.tmp`;
    writeFileSync(temporaryPath, JSON.stringify(envelope), { mode: 0o600 });
    try { renameSync(temporaryPath, this.outboxPath); }
    catch {
      rmSync(this.outboxPath, { force: true });
      renameSync(temporaryPath, this.outboxPath);
    }
    try { chmodSync(this.outboxPath, 0o600); } catch {}
  }
}
