import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CommunityNetwork } from "../../server/src/community/network.js";
import { MAX_COMMUNITY_FEED_ENTRY_VALUE_CHARS } from "../../server/src/community/resourceLimits.js";
import type { CommunityFeedPayload, CommunityReportSubmission } from "../../server/src/community/types.js";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function directory(): string {
  const value = mkdtempSync(join(tmpdir(), "email-shield-community-capacity-"));
  directories.push(value);
  return value;
}

function oversizedFeed(): CommunityFeedPayload {
  const now = new Date();
  return {
    version: 1,
    generatedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 60 * 60_000).toISOString(),
    entries: Array.from({ length: 2_200 }, (_, index) => ({
      type: "sender" as const,
      value: `${index}-${"x".repeat(MAX_COMMUNITY_FEED_ENTRY_VALUE_CHARS - String(index).length - 1)}`,
      confirmedThreat: false,
      ruleId: `large-${index}`,
    })),
  };
}

describe("community feed capacity degradation", () => {
  it("does not misreport a durably accepted report as rejected when feed publication reaches its resource boundary", () => {
    const network = new CommunityNetwork({ dataDirectory: directory(), serverEnabled: true });
    const internals = network as unknown as {
      aggregateStore: { buildFeedPayload: () => CommunityFeedPayload };
    };
    internals.aggregateStore.buildFeedPayload = oversizedFeed;

    const fingerprint = "f".repeat(64);
    const report: CommunityReportSubmission = {
      schemaVersion: 1,
      reporterProof: "a".repeat(64),
      campaignFingerprint: fingerprint,
      reportedAt: new Date().toISOString(),
      indicators: [{ type: "campaign", value: fingerprint }],
      evidenceCodes: ["TEST_EVIDENCE"],
      evidenceScore: 8,
      verdict: "high_risk",
    };

    const receipt = network.acceptExternalReport(report);
    expect(receipt).toMatchObject({ accepted: true, queued: false, campaignFingerprint: fingerprint });
    expect(network.lastRefreshError()).toContain("Community feed publication deferred");
  });
});
