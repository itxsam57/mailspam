import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EncryptedCommunityAggregateStore } from "../../server/src/community/aggregateStore.js";
import { CommunityFeedSigner, verifyCommunityFeed } from "../../server/src/community/signing.js";
import { COMMUNITY_REPORT_JOURNAL_FILE } from "../../server/src/community/storageFiles.js";
import type { CommunityReportSubmission } from "../../server/src/community/types.js";

const directories: string[] = [];
const CAMPAIGN = "a".repeat(64);
const CAPACITY_CLIENTS = 10_000;

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function report(index: number, now: Date): CommunityReportSubmission {
  return {
    schemaVersion: 1,
    reporterProof: createHash("sha256").update(`capacity-reporter-${index}`).digest("hex"),
    campaignFingerprint: CAMPAIGN,
    reportedAt: now.toISOString(),
    verdict: "high_risk",
    evidenceScore: 8,
    evidenceCodes: ["CAPACITY_ACCEPTANCE"],
    indicators: [
      { type: "campaign", value: CAMPAIGN },
      { type: "url_domain", value: "capacity-acceptance.example" },
    ],
  };
}

describe("community release-capacity qualification", () => {
  it("durably accepts 10,000 independent clients, survives restart, deduplicates reporters, and never bypasses trusted review", { timeout: 300_000 }, () => {
    const directory = mkdtempSync(join(tmpdir(), "email-shield-community-release-capacity-"));
    directories.push(directory);
    const acceptedAt = new Date("2026-08-11T00:00:00.000Z");
    const store = new EncryptedCommunityAggregateStore(directory, undefined, {
      now: () => acceptedAt,
      snapshotInterval: CAPACITY_CLIENTS * 2,
    });

    for (let index = 0; index < CAPACITY_CLIENTS; index++) {
      const receipt = store.accept(report(index, acceptedAt));
      expect(receipt.accepted).toBe(true);
      expect(receipt.independentReporters).toBe(index + 1);
    }
    store.close();

    expect(statSync(join(directory, COMMUNITY_REPORT_JOURNAL_FILE)).size).toBeGreaterThan(0);
    const restarted = new EncryptedCommunityAggregateStore(directory, undefined, { now: () => acceptedAt });
    // Raw client volume can create a warning but can never manufacture the
    // explicit human-action evidence, time spread, and trusted review required
    // for a signed Confirmed Threat.
    expect(restarted.stats()).toEqual({ campaigns: 1, warnings: 1, confirmed: 0 });
    expect(restarted.listReviewCandidates()).toEqual([]);
    expect(restarted.accept(report(CAPACITY_CLIENTS - 1, acceptedAt))).toMatchObject({
      duplicate: true,
      independentReporters: CAPACITY_CLIENTS,
      status: "warning",
    });

    const signer = new CommunityFeedSigner(directory);
    const verified = verifyCommunityFeed(signer.sign(restarted.buildFeedPayload(acceptedAt)), [signer.publicPem], acceptedAt);
    expect(verified?.entries).toHaveLength(2);
    expect(verified?.entries.every((entry) =>
      entry.type !== "identity"
      && entry.independentReports === CAPACITY_CLIENTS
      && entry.confirmedThreat === false
    )).toBe(true);
  });
});
