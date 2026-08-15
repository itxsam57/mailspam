import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EncryptedCommunityAggregateStore } from "../../server/src/community/aggregateStore.js";
import {
  LEGITIMATE_CONSENSUS_REPORTERS,
  LEGITIMATE_RULE_PREFIX,
  USER_BLOCKED_MESSAGE_CODE,
  USER_CONFIRMED_LEGITIMATE_CODE,
  USER_REPORTED_SCAM_CODE,
} from "../../server/src/community/feedback.js";
import type { CommunityReportSubmission } from "../../server/src/community/types.js";

const directories: string[] = [];
afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function store(): EncryptedCommunityAggregateStore {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-adaptive-learning-"));
  directories.push(directory);
  return new EncryptedCommunityAggregateStore(directory);
}

const campaignFingerprint = "d".repeat(64);

function reporterProof(label: string): string {
  return createHash("sha256").update(`adaptive-learning:${label}`).digest("hex");
}

function report(
  reporter: string,
  options: {
    verdict?: CommunityReportSubmission["verdict"];
    score?: number;
    codes?: string[];
  } = {},
): CommunityReportSubmission {
  return {
    schemaVersion: 1,
    reporterProof: reporterProof(reporter),
    campaignFingerprint,
    reportedAt: new Date().toISOString(),
    verdict: options.verdict ?? "safe",
    evidenceScore: options.score ?? 0,
    evidenceCodes: options.codes ?? [],
    indicators: [
      { type: "campaign", value: campaignFingerprint },
      { type: "sender", value: "rotating@example.test" },
    ],
  };
}

function legitimate(reporter: string): CommunityReportSubmission {
  return report(reporter, { codes: [USER_CONFIRMED_LEGITIMATE_CODE] });
}

describe("adaptive community learning", () => {
  it("publishes campaign-only legitimate consensus without creating a threat warning", () => {
    const aggregate = store();
    for (let index = 0; index < LEGITIMATE_CONSENSUS_REPORTERS; index++) {
      aggregate.accept(legitimate(`legit-${index}`));
    }

    expect(aggregate.stats()).toEqual({ campaigns: 1, warnings: 0, confirmed: 0 });
    expect(aggregate.buildFeedPayload().entries).toEqual([
      expect.objectContaining({
        type: "campaign",
        value: campaignFingerprint,
        confirmedThreat: false,
        independentReports: LEGITIMATE_CONSENSUS_REPORTERS,
        ruleId: expect.stringMatching(new RegExp(`^${LEGITIMATE_RULE_PREFIX}`)),
      }),
    ]);
  });

  it("does not let three nuisance blocks create a community threat warning", () => {
    const aggregate = store();
    for (const reporter of ["1", "2", "3"]) {
      aggregate.accept(report(reporter, { codes: [USER_BLOCKED_MESSAGE_CODE] }));
    }
    expect(aggregate.stats()).toEqual({ campaigns: 1, warnings: 0, confirmed: 0 });
    expect(aggregate.buildFeedPayload().entries).toEqual([]);
  });

  it("allows repeated independent blocks to become a warning without becoming Confirmed Threat", () => {
    const aggregate = store();
    for (let index = 0; index < 8; index++) {
      aggregate.accept(report(`block-${index}`, { codes: [USER_BLOCKED_MESSAGE_CODE] }));
    }
    expect(aggregate.stats()).toEqual({ campaigns: 1, warnings: 1, confirmed: 0 });
    expect(aggregate.buildFeedPayload().entries).toContainEqual(expect.objectContaining({
      type: "campaign",
      value: campaignFingerprint,
      confirmedThreat: false,
      independentReports: 8,
    }));
  });

  it("replaces reporter polarity instead of accumulating contradictory feedback", () => {
    const aggregate = store();
    for (let index = 0; index < LEGITIMATE_CONSENSUS_REPORTERS; index++) {
      aggregate.accept(legitimate(`person-${index}`));
    }
    expect(aggregate.buildFeedPayload().entries[0]?.ruleId).toMatch(new RegExp(`^${LEGITIMATE_RULE_PREFIX}`));

    // One unresolved explicit threat reporter immediately removes positive consensus.
    aggregate.accept(report("person-0", { codes: [USER_REPORTED_SCAM_CODE] }));
    expect(aggregate.stats()).toEqual({ campaigns: 1, warnings: 0, confirmed: 0 });
    expect(aggregate.buildFeedPayload().entries).toEqual([]);

    // Three explicit human Report Scam actions recover the warning model.
    aggregate.accept(report("person-1", { codes: [USER_REPORTED_SCAM_CODE] }));
    aggregate.accept(report("person-2", { codes: [USER_REPORTED_SCAM_CODE] }));
    expect(aggregate.stats()).toEqual({ campaigns: 1, warnings: 1, confirmed: 0 });
    const entries = aggregate.buildFeedPayload().entries;
    expect(entries.some((entry) => entry.type !== "identity" && entry.ruleId.startsWith(LEGITIMATE_RULE_PREFIX))).toBe(false);
    expect(entries).toContainEqual(expect.objectContaining({
      type: "campaign",
      value: campaignFingerprint,
      confirmedThreat: false,
      independentReports: 3,
    }));
  });

  it("rejects attempts to smuggle threat evidence into legitimate feedback", () => {
    const aggregate = store();
    expect(() => aggregate.accept(report("bad", {
      verdict: "high_risk",
      score: 10,
      codes: [USER_CONFIRMED_LEGITIMATE_CODE, "CREDENTIAL_PHISH_INTENT"],
    }))).toThrow("Legitimate feedback must be an isolated zero-risk Safe judgment");
  });
});
