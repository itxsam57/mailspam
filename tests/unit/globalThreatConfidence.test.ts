import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  COMMUNITY_REVIEW_MIN_SPAN_MS,
  EncryptedCommunityAggregateStore,
} from "../../server/src/community/aggregateStore.js";
import { USER_REPORTED_SCAM_CODE } from "../../server/src/community/feedback.js";
import type { CommunityReportSubmission } from "../../server/src/community/types.js";

const directories: string[] = [];
afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function proof(label: string): string {
  return createHash("sha256").update(`global-confidence:${label}`).digest("hex");
}

function harness(start = "2026-08-10T00:00:00.000Z") {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-global-confidence-"));
  directories.push(directory);
  let now = new Date(start);
  const aggregate = new EncryptedCommunityAggregateStore(directory, undefined, {
    now: () => new Date(now),
    snapshotInterval: 50,
  });
  return {
    aggregate,
    setNow(value: string) { now = new Date(value); },
    now() { return new Date(now); },
  };
}

function report(
  reporter: string,
  now: Date,
  campaign = "a".repeat(64),
  overrides: Partial<CommunityReportSubmission> = {},
): CommunityReportSubmission {
  return {
    schemaVersion: 1,
    reporterProof: proof(reporter),
    campaignFingerprint: campaign,
    reportedAt: now.toISOString(),
    verdict: "review",
    evidenceScore: 4,
    evidenceCodes: [USER_REPORTED_SCAM_CODE],
    indicators: [
      { type: "campaign", value: campaign },
      { type: "sender", value: "global-confidence@example.test" },
    ],
    ...overrides,
  };
}

function submitSpreadReports(
  aggregate: EncryptedCommunityAggregateStore,
  setNow: (value: string) => void,
  campaign = "a".repeat(64),
): void {
  for (const [index, value] of [
    "2026-08-10T00:00:00.000Z",
    "2026-08-10T01:00:00.000Z",
    "2026-08-10T02:00:00.000Z",
    "2026-08-10T03:00:00.000Z",
    "2026-08-11T07:00:00.000Z",
  ].entries()) {
    setNow(value);
    aggregate.accept(report(`spread-${index}`, new Date(value), campaign));
  }
}

describe("Global Shield server-owned confidence", () => {
  it("does not let forged client verdict or evidence score manufacture central trust", () => {
    const { aggregate, now } = harness();
    for (let index = 0; index < 5; index++) {
      aggregate.accept(report(`forged-${index}`, now(), "b".repeat(64), {
        verdict: "confirmed_threat",
        evidenceScore: 20,
        evidenceCodes: ["FORGED_CLIENT_CONFIRMED_SEVERITY"],
      }));
    }

    expect(aggregate.stats()).toEqual({ campaigns: 1, warnings: 0, confirmed: 0 });
    expect(aggregate.listReviewCandidates()).toEqual([]);
    expect(aggregate.buildFeedPayload().entries).toEqual([]);
  });

  it("deduplicates reporter identity so repeated reports cannot amplify corroboration", () => {
    const { aggregate, setNow, now } = harness();
    aggregate.accept(report("same-reporter", now(), "c".repeat(64)));
    setNow("2026-08-11T08:00:00.000Z");
    const receipt = aggregate.accept(report("same-reporter", now(), "c".repeat(64), {
      verdict: "confirmed_threat",
      evidenceScore: 20,
    }));

    expect(receipt.duplicate).toBe(true);
    expect(receipt.independentReporters).toBe(1);
    expect(aggregate.stats()).toEqual({ campaigns: 1, warnings: 0, confirmed: 0 });
    expect(aggregate.listReviewCandidates()).toEqual([]);
  });

  it("requires temporal spread before high corroboration becomes a review candidate", () => {
    const { aggregate, setNow, now } = harness();
    for (let index = 0; index < 5; index++) {
      setNow(`2026-08-10T0${index}:00:00.000Z`);
      aggregate.accept(report(`burst-${index}`, now(), "d".repeat(64)));
    }

    expect(aggregate.stats()).toEqual({ campaigns: 1, warnings: 1, confirmed: 0 });
    expect(aggregate.listReviewCandidates()).toEqual([]);
    expect(aggregate.buildFeedPayload().entries.every((entry) => entry.confirmedThreat === false)).toBe(true);
  });

  it("creates a persisted human-review candidate only after independent reports span time and UTC days", () => {
    const { aggregate, setNow } = harness();
    submitSpreadReports(aggregate, setNow, "e".repeat(64));

    const candidates = aggregate.listReviewCandidates();
    expect(candidates).toHaveLength(1);
    expect(candidates[0]).toEqual(expect.objectContaining({
      campaignFingerprint: "e".repeat(64),
      independentReporters: 5,
      strongReporters: 5,
      distinctUtcDays: 2,
    }));
    expect(candidates[0]!.observedSpanMs).toBeGreaterThanOrEqual(COMMUNITY_REVIEW_MIN_SPAN_MS);
    expect(aggregate.stats()).toEqual({ campaigns: 1, warnings: 1, confirmed: 0 });
    expect(aggregate.buildFeedPayload().entries.every((entry) => entry.confirmedThreat === false)).toBe(true);
  });

  it("publishes Confirmed Threat only after explicit trusted human approval", () => {
    const { aggregate, setNow } = harness();
    submitSpreadReports(aggregate, setNow, "f".repeat(64));
    expect(aggregate.buildFeedPayload().entries.every((entry) => entry.confirmedThreat === false)).toBe(true);

    const resolution = aggregate.resolveReviewCandidate({
      campaignFingerprint: "f".repeat(64),
      decision: "approved",
      reviewerId: "reviewer-001",
      reason: "Independent reports persisted across the required observation window and the campaign was manually verified.",
    });

    expect(resolution.decision).toBe("approved");
    expect(resolution.reporterHistoriesUpdated).toBe(5);
    expect(aggregate.listReviewCandidates()).toEqual([]);
    expect(aggregate.stats()).toEqual({ campaigns: 1, warnings: 0, confirmed: 1 });
    expect(aggregate.buildFeedPayload().entries).toContainEqual(expect.objectContaining({
      type: "campaign",
      value: "f".repeat(64),
      confirmedThreat: true,
      independentReports: 5,
    }));
  });

  it("keeps a rejected campaign non-confirmed and requires genuinely new corroboration before re-review", () => {
    const { aggregate, setNow, now } = harness();
    submitSpreadReports(aggregate, setNow, "1".repeat(64));
    aggregate.resolveReviewCandidate({
      campaignFingerprint: "1".repeat(64),
      decision: "rejected",
      reviewerId: "reviewer-002",
      reason: "Manual verification found the campaign indicators insufficient for a global confirmed rule.",
    });

    expect(aggregate.stats()).toEqual({ campaigns: 1, warnings: 1, confirmed: 0 });
    expect(aggregate.listReviewCandidates()).toEqual([]);
    expect(aggregate.buildFeedPayload().entries.every((entry) => entry.confirmedThreat === false)).toBe(true);

    setNow("2026-08-12T08:00:00.000Z");
    aggregate.accept(report("spread-0", now(), "1".repeat(64)));
    expect(aggregate.listReviewCandidates()).toEqual([]);

    aggregate.accept(report("new-after-rejection", now(), "1".repeat(64)));
    expect(aggregate.listReviewCandidates()).toHaveLength(1);
  });

  it("uses resolved review outcomes as bounded historical reporter confidence", () => {
    const { aggregate, setNow } = harness();
    const reporters = ["rep-0", "rep-1", "rep-2", "rep-3", "rep-4"];

    for (let caseIndex = 0; caseIndex < 3; caseIndex++) {
      const campaign = String(caseIndex + 2).repeat(64);
      const times = [
        `2026-08-${10 + caseIndex}T00:00:00.000Z`,
        `2026-08-${10 + caseIndex}T01:00:00.000Z`,
        `2026-08-${10 + caseIndex}T02:00:00.000Z`,
        `2026-08-${10 + caseIndex}T03:00:00.000Z`,
        `2026-08-${11 + caseIndex}T07:00:00.000Z`,
      ];
      for (let index = 0; index < reporters.length; index++) {
        setNow(times[index]!);
        aggregate.accept(report(reporters[index]!, new Date(times[index]!), campaign));
      }
      aggregate.resolveReviewCandidate({
        campaignFingerprint: campaign,
        decision: "rejected",
        reviewerId: "reviewer-reputation",
        reason: "Controlled reputation certification rejection.",
      });
    }

    const fourth = "9".repeat(64);
    for (const [index, value] of [
      "2026-08-13T08:00:00.000Z",
      "2026-08-13T09:00:00.000Z",
      "2026-08-13T10:00:00.000Z",
      "2026-08-13T11:00:00.000Z",
      "2026-08-14T15:00:00.000Z",
    ].entries()) {
      setNow(value);
      aggregate.accept(report(reporters[index]!, new Date(value), fourth));
    }

    // Five independent reporters are still present, but three trusted review
    // outcomes established a poor historical accuracy record. Reputation can
    // therefore delay escalation; it can never create confirmation by itself.
    expect(aggregate.listReviewCandidates()).toEqual([]);
    expect(aggregate.stats().confirmed).toBe(0);
  });
});
