import { describe, expect, it } from "vitest";
import { FixtureAdapter, type FixtureMessage } from "../../server/src/adapters/fixtures/fixtureAdapter.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { quickScan } from "../../server/src/workflows/scanWorkflows.js";
import {
  scanStallReason,
  snapshotVerifiedFeedAndRefresh,
} from "../../server/src/api/scanStream.js";

function fixtureMessage(index: number): FixtureMessage {
  return {
    id: `message-${index}`,
    folder: "inbox",
    providerFolderName: "INBOX",
    rawEml: [
      `From: Example ${index} <sender${index}@example.com>`,
      `To: user@example.com`,
      `Subject: Routine update ${index}`,
      `Message-ID: <message-${index}@example.com>`,
      `Date: Tue, 4 Aug 2026 10:00:0${index} +0000`,
      "Authentication-Results: mx.example; dkim=pass; spf=pass; dmarc=pass",
      "Content-Type: text/plain; charset=utf-8",
      "",
      `This is a routine account update number ${index}. No action is required.`,
    ].join("\r\n"),
  };
}

describe("bounded scan progress runtime", () => {
  it("keeps the quick-scan message limit while yielding smaller progress batches", async () => {
    const adapter = new FixtureAdapter(
      "icloud",
      Array.from({ length: 5 }, (_, index) => fixtureMessage(index + 1)),
    );
    const personalPolicy = new InMemoryPersonalPolicyStore();
    const controller = new AbortController();
    const results = [];

    for await (const progress of quickScan(
      adapter,
      {
        personalPolicy,
        threatFeed: { getVerifiedEntries: () => [] },
      },
      controller.signal,
      2,
      5,
    )) {
      results.push(progress);
    }

    expect(results.map((progress) => progress.counters.examined)).toEqual([2, 4, 5]);
    expect(results.map((progress) => progress.done)).toEqual([false, false, true]);
    expect(results.flatMap((progress) => progress.diagnosticSummaries)).toHaveLength(5);
  });

  it("takes the verified feed snapshot immediately instead of awaiting network refresh", async () => {
    let refreshStarted = false;
    let releaseRefresh: (() => void) | undefined;
    const refresh = new Promise<void>((resolve) => { releaseRefresh = resolve; });
    const community = {
      remoteUrl: "https://community.example",
      getVerifiedEntries: () => null,
      refreshFeed: async () => {
        refreshStarted = true;
        await refresh;
      },
    };

    const snapshot = snapshotVerifiedFeedAndRefresh(community as never);
    expect(snapshot).toBeNull();
    expect(refreshStarted).toBe(false);

    await Promise.resolve();
    expect(refreshStarted).toBe(true);
    releaseRefresh?.();
    await refresh;
  });

  it("distinguishes first-result stalls from later page stalls", () => {
    expect(scanStallReason(
      { startedAt: 0, lastProgressAt: 0, progressSeen: false },
      179_999,
      180_000,
      120_000,
    )).toBeNull();
    expect(scanStallReason(
      { startedAt: 0, lastProgressAt: 0, progressSeen: false },
      180_000,
      180_000,
      120_000,
    )).toContain("first bounded message batch");
    expect(scanStallReason(
      { startedAt: 0, lastProgressAt: 40_000, progressSeen: true },
      160_000,
      180_000,
      120_000,
    )).toContain("stopped returning message batches");
  });
});
