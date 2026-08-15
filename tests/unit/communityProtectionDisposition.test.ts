import { createHash } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { EncryptedCommunityAggregateStore } from "../../server/src/community/aggregateStore.js";
import { USER_REPORTED_SCAM_CODE } from "../../server/src/community/feedback.js";
import { campaignFingerprint } from "../../server/src/community/fingerprint.js";
import type { CommunityReportSubmission } from "../../server/src/community/types.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";
import {
  isCommunityWarningQuarantineResult,
  isDurableAutoTrashResult,
} from "../../server/src/workflows/durableProtection.js";

const directories: string[] = [];
afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function aggregate(now?: () => Date): EncryptedCommunityAggregateStore {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-disposition-"));
  directories.push(directory);
  return new EncryptedCommunityAggregateStore(directory, undefined, now ? { now } : {});
}

function envelope(): CanonicalEnvelope {
  return {
    provider: "imap",
    accountProof: "protected-account",
    messageId: "campaign-message",
    providerNativeId: "campaign-native",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Updates", address: "rotating@campaign.example", domain: "campaign.example" },
    replyTo: null,
    subject: "Routine campaign notice",
    date: new Date(0).toISOString(),
    authentication: { providerTrust: "trusted", spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview: "Readable content that is otherwise clean so community disposition is isolated in this regression.",
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: {
      fetchedAt: new Date(0).toISOString(),
      sizeBytes: 500,
      encoding: "plain",
      contentCoverage: "complete",
    },
  };
}

function submission(input: CanonicalEnvelope, reporter: string, strong = false, reportedAt = new Date()): CommunityReportSubmission {
  const fingerprint = campaignFingerprint(input);
  return {
    schemaVersion: 1,
    reporterProof: createHash("sha256").update(`disposition:${reporter}`).digest("hex"),
    campaignFingerprint: fingerprint,
    reportedAt: reportedAt.toISOString(),
    verdict: strong ? "high_risk" : "safe",
    evidenceScore: strong ? 6 : 0,
    evidenceCodes: strong
      ? [USER_REPORTED_SCAM_CODE, "CALLBACK_SCAM_INTENT", "DMARC_FAIL"]
      : [USER_REPORTED_SCAM_CODE],
    indicators: [
      { type: "campaign", value: fingerprint },
      { type: "sender", value: input.from.address! },
    ],
  };
}

function scan(input: CanonicalEnvelope, policy: InMemoryPersonalPolicyStore, entries: ReturnType<EncryptedCommunityAggregateStore["buildFeedPayload"]>["entries"]) {
  return scanMessage(input, {
    personalPolicy: policy,
    threatFeed: { getVerifiedEntries: () => entries },
  });
}

describe("community protection disposition ladder", () => {
  it("protects the reporting user locally while one report remains invisible to other installations", () => {
    const input = envelope();
    const central = aggregate();
    central.accept(submission(input, "reporter-1"));
    expect(central.buildFeedPayload().entries).toEqual([]);

    const reporterPolicy = new InMemoryPersonalPolicyStore();
    reporterPolicy.reportCampaign(campaignFingerprint(input));
    const reporterResult = scan(input, reporterPolicy, []);
    expect(reporterResult.scored.verdict).toBe("confirmed_threat");
    expect(reporterResult.scored.evidence).toContainEqual(expect.objectContaining({ code: "LOCALLY_REPORTED_SCAM_CAMPAIGN" }));
    expect(isDurableAutoTrashResult(reporterResult)).toBe(true);

    const otherResult = scan(input, new InMemoryPersonalPolicyStore(), []);
    expect(otherResult.scored.verdict).toBe("safe");
    expect(isDurableAutoTrashResult(otherResult)).toBe(false);
    expect(isCommunityWarningQuarantineResult(otherResult)).toBe(false);
  });

  it("quarantines a warning-level campaign for non-reporting users without granting global Trash authority", () => {
    const input = envelope();
    const central = aggregate();
    for (const reporter of ["1", "2", "3"]) central.accept(submission(input, reporter));
    const feed = central.buildFeedPayload();
    expect(central.stats()).toEqual({ campaigns: 1, warnings: 1, confirmed: 0 });
    expect(feed.entries.length).toBeGreaterThan(0);
    expect(feed.entries.every((entry) => entry.type === "identity" || entry.confirmedThreat === false)).toBe(true);

    const result = scan(input, new InMemoryPersonalPolicyStore(), feed.entries);
    expect(result.scored.evidence).toContainEqual(expect.objectContaining({ code: "GLOBAL_WARNING_MATCH" }));
    expect(result.scored.verdict).not.toBe("confirmed_threat");
    expect(isCommunityWarningQuarantineResult(result)).toBe(true);
    expect(isDurableAutoTrashResult(result)).toBe(false);
  });

  it("auto-trashes only a globally confirmed campaign that passed time-spread corroboration and trusted review", () => {
    const input = envelope();
    let now = new Date("2026-08-10T00:00:00.000Z");
    const central = aggregate(() => new Date(now));
    for (const [index, value] of [
      "2026-08-10T00:00:00.000Z",
      "2026-08-10T01:00:00.000Z",
      "2026-08-10T02:00:00.000Z",
      "2026-08-10T03:00:00.000Z",
      "2026-08-11T07:00:00.000Z",
    ].entries()) {
      now = new Date(value);
      central.accept(submission(input, `reviewed-${index}`, true, now));
    }
    expect(central.stats()).toEqual({ campaigns: 1, warnings: 1, confirmed: 0 });
    central.resolveReviewCandidate({
      campaignFingerprint: campaignFingerprint(input),
      decision: "approved",
      reviewerId: "disposition-reviewer",
      reason: "Independent reports and campaign evidence were manually verified before granting global Trash authority.",
    });

    const feed = central.buildFeedPayload(now);
    expect(central.stats()).toEqual({ campaigns: 1, warnings: 0, confirmed: 1 });
    expect(feed.entries).toContainEqual(expect.objectContaining({
      type: "campaign",
      value: campaignFingerprint(input),
      confirmedThreat: true,
      independentReports: 5,
    }));

    const result = scan(input, new InMemoryPersonalPolicyStore(), feed.entries);
    expect(result.scored.verdict).toBe("confirmed_threat");
    expect(result.scored.evidence).toContainEqual(expect.objectContaining({ code: "GLOBAL_CONFIRMED_MATCH" }));
    expect(isCommunityWarningQuarantineResult(result)).toBe(false);
    expect(isDurableAutoTrashResult(result)).toBe(true);
  });
});
