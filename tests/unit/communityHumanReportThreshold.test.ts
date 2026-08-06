import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EncryptedCommunityAggregateStore } from "../../server/src/community/aggregateStore.js";
import type { CommunityReportSubmission } from "../../server/src/community/types.js";

const directories: string[] = [];
afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function store(): EncryptedCommunityAggregateStore {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-human-report-"));
  directories.push(directory);
  return new EncryptedCommunityAggregateStore(directory);
}

function reporterProof(label: string): string {
  return createHash("sha256").update(`human-report-test:${label}`).digest("hex");
}

function safeReport(reporter: string): CommunityReportSubmission {
  const campaignFingerprint = "c".repeat(64);
  return {
    schemaVersion: 1,
    reporterProof: reporterProof(reporter),
    campaignFingerprint,
    reportedAt: new Date().toISOString(),
    verdict: "safe",
    evidenceScore: 0,
    evidenceCodes: [],
    indicators: [
      { type: "campaign", value: campaignFingerprint },
      { type: "sender", value: "reported-by-humans@example.test" },
    ],
  };
}

describe("explicit human report weighting", () => {
  it("creates a warning from three distinct human reports even when the old detector called the mail Safe", () => {
    const aggregate = store();
    for (const reporter of ["1", "2", "3"]) aggregate.accept(safeReport(reporter));
    const feed = aggregate.buildFeedPayload();
    expect(aggregate.stats()).toEqual({ campaigns: 1, warnings: 1, confirmed: 0 });
    expect(feed.entries).toContainEqual(expect.objectContaining({
      type: "campaign",
      value: "c".repeat(64),
      confirmedThreat: false,
      independentReports: 3,
    }));
  });

  it("does not turn five evidence-free human reports into a Confirmed Threat", () => {
    const aggregate = store();
    for (const reporter of ["1", "2", "3", "4", "5"]) aggregate.accept(safeReport(reporter));
    const feed = aggregate.buildFeedPayload();
    expect(aggregate.stats()).toEqual({ campaigns: 1, warnings: 1, confirmed: 0 });
    expect(feed.entries.length).toBeGreaterThan(0);
    expect(feed.entries.every((entry) => entry.type === "identity" || entry.confirmedThreat === false)).toBe(true);
  });

  it("rejects reports with forged future or excessively old timestamps", () => {
    const aggregate = store();
    expect(() => aggregate.accept({
      ...safeReport("1"),
      reportedAt: new Date(Date.now() + 10 * 60_000).toISOString(),
    })).toThrow("outside the accepted submission window");
    expect(() => aggregate.accept({
      ...safeReport("2"),
      reportedAt: new Date(Date.now() - 31 * 24 * 60 * 60_000).toISOString(),
    })).toThrow("outside the accepted submission window");
  });
});
