import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EncryptedCommunityAggregateStore } from "../../server/src/community/aggregateStore.js";
import { CommunityNetwork } from "../../server/src/community/network.js";
import {
  createEncryptedCommunityBackup,
  MAX_COMMUNITY_BACKUP_SOURCE_BYTES,
} from "../../server/src/community/operations.js";
import {
  COMMUNITY_STORAGE_KEY_BYTES,
  MAX_COMMUNITY_AGGREGATE_DATABASE_BYTES,
  MAX_COMMUNITY_AUTHORITATIVE_SOURCE_BYTES,
  MAX_COMMUNITY_REPORT_JOURNAL_BYTES,
  MAX_COMMUNITY_SIGNING_KEY_FILE_BYTES,
} from "../../server/src/community/resourceLimits.js";
import {
  COMMUNITY_REPORT_DATABASE_FILE,
  COMMUNITY_REPORT_KEY_FILE,
} from "../../server/src/community/storageFiles.js";
import type { CommunityReportSubmission } from "../../server/src/community/types.js";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0).reverse()) rmSync(directory, { recursive: true, force: true });
});

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-community-recoverable-bound-"));
  directories.push(directory);
  return directory;
}

function report(): CommunityReportSubmission {
  const fingerprint = "a".repeat(64);
  return {
    schemaVersion: 1,
    reporterProof: "b".repeat(64),
    campaignFingerprint: fingerprint,
    reportedAt: new Date().toISOString(),
    verdict: "high_risk",
    evidenceScore: 8,
    evidenceCodes: ["RECOVERABLE_BOUND_TEST"],
    indicators: [
      { type: "campaign", value: fingerprint },
      { type: "url_domain", value: "recoverable-bound.example" },
    ],
  };
}

describe("recoverable community aggregate storage boundary", () => {
  it("derives the production database ceiling from the same authoritative recovery source limit", () => {
    expect(MAX_COMMUNITY_BACKUP_SOURCE_BYTES).toBe(MAX_COMMUNITY_AUTHORITATIVE_SOURCE_BYTES);
    expect(
      MAX_COMMUNITY_AGGREGATE_DATABASE_BYTES +
      MAX_COMMUNITY_REPORT_JOURNAL_BYTES +
      (2 * MAX_COMMUNITY_SIGNING_KEY_FILE_BYTES) +
      COMMUNITY_STORAGE_KEY_BYTES,
    ).toBe(MAX_COMMUNITY_AUTHORITATIVE_SOURCE_BYTES);
  });

  it("rejects an oversized aggregate file before reading it or creating/loading a storage key", () => {
    const directory = temporaryDirectory();
    const databasePath = join(directory, COMMUNITY_REPORT_DATABASE_FILE);
    writeFileSync(databasePath, "");
    truncateSync(databasePath, MAX_COMMUNITY_AGGREGATE_DATABASE_BYTES + 1);
    const keyPath = join(directory, COMMUNITY_REPORT_KEY_FILE);

    expect(() => new EncryptedCommunityAggregateStore(directory).stats())
      .toThrow("recoverable storage boundary");
    expect(existsSync(keyPath)).toBe(false);
  });

  it("keeps ordinary production state inside the recovery-compatible boundary and backs it up", () => {
    const directory = temporaryDirectory();
    const network = new CommunityNetwork({ dataDirectory: directory, serverEnabled: true });
    network.acceptExternalReport(report());
    const databasePath = join(directory, COMMUNITY_REPORT_DATABASE_FILE);
    expect(statSync(databasePath).size).toBeLessThanOrEqual(MAX_COMMUNITY_AGGREGATE_DATABASE_BYTES);
    expect(readFileSync(join(directory, COMMUNITY_REPORT_KEY_FILE)).length).toBe(COMMUNITY_STORAGE_KEY_BYTES);

    const backup = join(temporaryDirectory(), "recoverable.eshield");
    const result = createEncryptedCommunityBackup({
      dataDirectory: directory,
      backupPath: backup,
      passphrase: "recoverable storage boundary test passphrase",
    });
    expect(result.sourceBytes).toBeLessThanOrEqual(MAX_COMMUNITY_AUTHORITATIVE_SOURCE_BYTES);
    expect(existsSync(backup)).toBe(true);
  });

  it("rejects configured signing material that would violate the reserved recovery key budget", () => {
    const directory = temporaryDirectory();
    const backup = join(temporaryDirectory(), "oversized-key.eshield");
    expect(() => createEncryptedCommunityBackup({
      dataDirectory: directory,
      backupPath: backup,
      passphrase: "configured signing key size boundary test",
      configuredSigningKeys: {
        privatePem: "x".repeat(MAX_COMMUNITY_SIGNING_KEY_FILE_BYTES + 1),
        publicPem: "not-reached",
      },
    })).toThrow("signing key material exceeds the recovery size limit");
    expect(existsSync(backup)).toBe(false);
  });

  it("locks fail-before-persist sizing on the aggregate writer", () => {
    const source = readFileSync(join(process.cwd(), "src/community/aggregateStore.ts"), "utf8");
    const candidateCheck = source.indexOf("this.assertSnapshotCapacityBytes(candidatePlaintextBytes)");
    const journalAppend = source.indexOf("this.appendJournal(line)");
    const writer = source.indexOf("private writeDatabase(database");
    const writerPrecheck = source.indexOf("this.assertSnapshotCapacity(database)", writer);
    const writerEncryption = source.indexOf("this.encryptJson(database, SNAPSHOT_AAD)", writer);
    const writerFinalCheck = source.indexOf('Buffer.byteLength(serialized, "utf8") > MAX_COMMUNITY_AGGREGATE_DATABASE_BYTES', writer);
    const writerPersist = source.indexOf("writeFileSync(temporaryPath, serialized", writer);
    expect(candidateCheck).toBeGreaterThan(0);
    expect(journalAppend).toBeGreaterThan(candidateCheck);
    expect(writerPrecheck).toBeGreaterThan(writer);
    expect(writerEncryption).toBeGreaterThan(writerPrecheck);
    expect(writerFinalCheck).toBeGreaterThan(writerEncryption);
    expect(writerPersist).toBeGreaterThan(writerFinalCheck);
  });
});
