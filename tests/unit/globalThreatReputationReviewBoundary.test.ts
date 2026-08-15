import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  DEFAULT_COMMUNITY_THRESHOLDS,
  EncryptedCommunityAggregateStore,
} from "../../server/src/community/aggregateStore.js";
import { USER_REPORTED_SCAM_CODE } from "../../server/src/community/feedback.js";
import type { CommunityReportSubmission } from "../../server/src/community/types.js";

const directories: string[] = [];
afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function proof(label: string): string {
  return createHash("sha256").update(`review-boundary:${label}`).digest("hex");
}

function submission(reporter: string, campaign: string, at: Date): CommunityReportSubmission {
  return {
    schemaVersion: 1,
    reporterProof: proof(reporter),
    campaignFingerprint: campaign,
    reportedAt: at.toISOString(),
    verdict: "review",
    evidenceScore: 4,
    evidenceCodes: [USER_REPORTED_SCAM_CODE],
    indicators: [
      { type: "campaign", value: campaign },
      { type: "sender", value: "review-boundary@example.test" },
    ],
  };
}

describe("Global Shield retained review evidence", () => {
  it("never grants a reporter reputation from a human decision made before that reporter arrived", () => {
    const directory = mkdtempSync(join(tmpdir(), "email-shield-review-boundary-"));
    directories.push(directory);
    let now = new Date("2026-08-01T00:00:00.000Z");
    const aggregate = new EncryptedCommunityAggregateStore(directory, {
      ...DEFAULT_COMMUNITY_THRESHOLDS,
      // This boundary deliberately distinguishes the correct 22.5 score from
      // the buggy retroactive-reputation score of 23.75.
      confirmedWeight: 23,
    }, {
      now: () => new Date(now),
      snapshotInterval: 50,
    });
    const setNow = (value: string) => { now = new Date(value); };

    const approved = "1".repeat(64);
    const approvalTimes = [
      "2026-08-01T00:00:00.000Z",
      "2026-08-01T01:00:00.000Z",
      "2026-08-01T02:00:00.000Z",
      "2026-08-01T03:00:00.000Z",
      "2026-08-02T07:00:00.000Z",
    ];
    for (const [index, value] of approvalTimes.entries()) {
      setNow(value);
      aggregate.accept(submission(`approval-seed-${index}`, approved, now));
    }
    aggregate.resolveReviewCandidate({
      campaignFingerprint: approved,
      decision: "approved",
      reviewerId: "review-boundary",
      reason: "Controlled approval before the late reporter exists.",
    });

    // This reporter arrives only after the human approval. The approval must
    // never be back-filled into its reputation history.
    setNow("2026-08-03T09:00:00.000Z");
    aggregate.accept(submission("late-reporter", approved, now));

    for (let caseIndex = 0; caseIndex < 3; caseIndex++) {
      const campaign = ["2", "3", "4"][caseIndex]!.repeat(64);
      const day = 4 + (caseIndex * 2);
      const cohort = [
        "late-reporter",
        `reject-${caseIndex}-1`,
        `reject-${caseIndex}-2`,
        `reject-${caseIndex}-3`,
        `reject-${caseIndex}-4`,
      ];
      const times = [
        `2026-08-${String(day).padStart(2, "0")}T00:00:00.000Z`,
        `2026-08-${String(day).padStart(2, "0")}T01:00:00.000Z`,
        `2026-08-${String(day).padStart(2, "0")}T02:00:00.000Z`,
        `2026-08-${String(day).padStart(2, "0")}T03:00:00.000Z`,
        `2026-08-${String(day + 1).padStart(2, "0")}T07:00:00.000Z`,
      ];
      for (const [index, value] of times.entries()) {
        setNow(value);
        aggregate.accept(submission(cohort[index]!, campaign, now));
      }
      expect(aggregate.listReviewCandidates()).toContainEqual(expect.objectContaining({ campaignFingerprint: campaign }));
      aggregate.resolveReviewCandidate({
        campaignFingerprint: campaign,
        decision: "rejected",
        reviewerId: "review-boundary",
        reason: "Controlled rejection used to establish post-arrival reputation only.",
      });
    }

    const probe = "5".repeat(64);
    const probeReporters = ["late-reporter", "probe-1", "probe-2", "probe-3", "probe-4"];
    const probeTimes = [
      "2026-08-10T00:00:00.000Z",
      "2026-08-10T01:00:00.000Z",
      "2026-08-10T02:00:00.000Z",
      "2026-08-10T03:00:00.000Z",
      "2026-08-11T07:00:00.000Z",
    ];
    for (const [index, value] of probeTimes.entries()) {
      setNow(value);
      aggregate.accept(submission(probeReporters[index]!, probe, now));
    }

    // Correct history: late reporter has 3 rejected cases, 0 aligned -> 0.5x.
    // Probe weight = 2.5 + 4*5 = 22.5, below the test boundary of 23.
    // A retroactively inherited approval would produce 23.75 and incorrectly
    // create a review candidate, so this assertion fails if that bug returns.
    expect(aggregate.listReviewCandidates().some((candidate) => candidate.campaignFingerprint === probe)).toBe(false);
  });
});