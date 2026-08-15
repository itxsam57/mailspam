import { createHash } from "node:crypto";
import { appendFileSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  COMMUNITY_REPORT_RETENTION_MS,
  EncryptedCommunityAggregateStore,
} from "../../server/src/community/aggregateStore.js";
import { USER_REPORTED_SCAM_CODE } from "../../server/src/community/feedback.js";
import { CommunityFeedSigner, verifyCommunityFeed } from "../../server/src/community/signing.js";
import { COMMUNITY_REPORT_JOURNAL_FILE } from "../../server/src/community/storageFiles.js";
import type { CommunityReportSubmission } from "../../server/src/community/types.js";

const directories: string[] = [];
const CAMPAIGN = "a".repeat(64);

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-community-capacity-"));
  directories.push(directory);
  return directory;
}

function proof(index: number): string {
  return createHash("sha256").update(`capacity-reporter-${index}`).digest("hex");
}

function report(index: number, now: Date): CommunityReportSubmission {
  return {
    schemaVersion: 1,
    reporterProof: proof(index),
    campaignFingerprint: CAMPAIGN,
    reportedAt: now.toISOString(),
    verdict: "high_risk",
    evidenceScore: 8,
    evidenceCodes: [USER_REPORTED_SCAM_CODE, "CAPACITY_ACCEPTANCE"],
    indicators: [
      { type: "campaign", value: CAMPAIGN },
      { type: "url_domain", value: "capacity-acceptance.example" },
    ],
  };
}

describe("community capacity, journal recovery and fixed retention", () => {
  it("preserves independent-client durability, restart recovery and deduplication without auto-confirming a same-burst campaign", () => {
    const directory = temporaryDirectory();
    const acceptedAt = new Date("2026-08-11T00:00:00.000Z");
    const representativeClients = 100;
    const store = new EncryptedCommunityAggregateStore(directory, undefined, {
      now: () => acceptedAt,
      snapshotInterval: representativeClients * 2,
    });

    for (let index = 0; index < representativeClients; index++) {
      const receipt = store.accept(report(index, acceptedAt));
      expect(receipt.accepted).toBe(true);
      expect(receipt.independentReporters).toBe(index + 1);
    }
    store.close();

    const journalPath = join(directory, COMMUNITY_REPORT_JOURNAL_FILE);
    expect(statSync(journalPath).size).toBeGreaterThan(0);

    const restarted = new EncryptedCommunityAggregateStore(directory, undefined, { now: () => acceptedAt });
    expect(restarted.stats()).toEqual({ campaigns: 1, warnings: 1, confirmed: 0 });
    const duplicate = restarted.accept(report(representativeClients - 1, acceptedAt));
    expect(duplicate).toMatchObject({ duplicate: true, independentReporters: representativeClients, status: "warning" });

    const signer = new CommunityFeedSigner(directory);
    const signed = signer.sign(restarted.buildFeedPayload(acceptedAt));
    const verified = verifyCommunityFeed(signed, [signer.publicPem], acceptedAt);
    expect(verified?.entries).toHaveLength(2);
    expect(verified?.entries.every((entry) => entry.type !== "identity" && !entry.confirmedThreat && entry.independentReports === representativeClients)).toBe(true);
  });

  it("removes expired reporter data, bounded reputation-derived state, and published intelligence at the fixed retention boundary", () => {
    const directory = temporaryDirectory();
    let now = new Date("2026-01-01T00:00:00.000Z");
    const store = new EncryptedCommunityAggregateStore(directory, undefined, { now: () => now });
    for (let index = 0; index < 5; index++) store.accept(report(index, now));
    expect(store.stats()).toEqual({ campaigns: 1, warnings: 1, confirmed: 0 });

    now = new Date(now.getTime() + COMMUNITY_REPORT_RETENTION_MS + 1);
    expect(store.stats()).toEqual({ campaigns: 0, warnings: 0, confirmed: 0 });
    expect(store.buildFeedPayload(now).entries).toEqual([]);

    const restarted = new EncryptedCommunityAggregateStore(directory, undefined, { now: () => now });
    expect(restarted.stats()).toEqual({ campaigns: 0, warnings: 0, confirmed: 0 });
  });

  it("recovers committed journal records and discards only an incomplete final append", () => {
    const directory = temporaryDirectory();
    const now = new Date("2026-08-11T00:00:00.000Z");
    const store = new EncryptedCommunityAggregateStore(directory, undefined, { now: () => now, snapshotInterval: 100 });
    store.accept(report(0, now));
    store.accept(report(1, now));
    const journalPath = join(directory, COMMUNITY_REPORT_JOURNAL_FILE);
    const committedBytes = statSync(journalPath).size;
    appendFileSync(journalPath, "{interrupted-final-record", { encoding: "utf8" });

    const restarted = new EncryptedCommunityAggregateStore(directory, undefined, { now: () => now, snapshotInterval: 100 });
    expect(restarted.stats().campaigns).toBe(1);
    expect(statSync(journalPath).size).toBe(committedBytes);
    expect(restarted.accept(report(2, now))).toMatchObject({ independentReporters: 3, status: "warning" });
  });

  it("skips stale journal records already represented by a newer durable snapshot", () => {
    const directory = temporaryDirectory();
    let now = new Date("2026-08-11T00:00:00.000Z");
    const journalPath = join(directory, COMMUNITY_REPORT_JOURNAL_FILE);
    const first = new EncryptedCommunityAggregateStore(directory, undefined, { now: () => now, snapshotInterval: 100 });
    first.accept(report(0, now));
    now = new Date(now.getTime() + 1);
    first.accept(report(1, now));
    const staleJournal = readFileSync(journalPath);
    first.close();

    now = new Date(now.getTime() + 1);
    const checkpointing = new EncryptedCommunityAggregateStore(directory, undefined, { now: () => now, snapshotInterval: 1 });
    checkpointing.accept(report(2, now));
    checkpointing.close();
    expect(statSync(journalPath).size).toBe(0);

    // Simulates a crash window where snapshot replacement succeeded but the
    // pre-snapshot WAL remained on disk. Recovery must be idempotent.
    writeFileSync(journalPath, staleJournal, { mode: 0o600 });
    const recovered = new EncryptedCommunityAggregateStore(directory, undefined, { now: () => now, snapshotInterval: 100 });
    expect(recovered.stats()).toEqual({ campaigns: 1, warnings: 1, confirmed: 0 });
    expect(recovered.accept(report(1, now))).toMatchObject({ duplicate: true, independentReporters: 3, status: "warning" });
  });

  it("rejects an external journal mutation while the authoritative writer is active", () => {
    const directory = temporaryDirectory();
    const now = new Date("2026-08-11T00:00:00.000Z");
    const store = new EncryptedCommunityAggregateStore(directory, undefined, { now: () => now });
    store.accept(report(0, now));
    appendFileSync(join(directory, COMMUNITY_REPORT_JOURNAL_FILE), "external-mutation\n", { encoding: "utf8" });

    expect(() => store.accept(report(1, now))).toThrow();
    store.close();
  });
});
