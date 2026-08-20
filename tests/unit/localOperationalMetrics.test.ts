import { describe, expect, it } from "vitest";
import { LocalOperationalMetrics } from "../../server/src/api/localOperationalMetrics.js";

describe("privacy-safe local operational metrics", () => {
  it("uses fixed providers/operations and records aggregate success, failure, cancellation and review outcomes", () => {
    let now = 1_000;
    const metrics = new LocalOperationalMetrics(() => now);
    const connect = metrics.beginAdapterOperation("gmail", "connect");
    now += 25;
    connect("succeeded");
    connect("failed");
    const fetchFailure = metrics.beginAdapterOperation("gmail", "fetch_page");
    now += 5;
    fetchFailure("failed");
    const cancellation = metrics.beginAdapterOperation("gmail", "list_folders");
    cancellation("cancelled");
    metrics.recordScanStarted("gmail");
    metrics.recordScanFinished("gmail", "completed", {
      examined: 5, safe: 2, review: 1, highRisk: 1, confirmedThreat: 0, unknown: 1, skipped: 0, malformed: 1,
    });
    metrics.recordFalsePositiveApproval();
    metrics.recordAbuseReport(true);
    metrics.recordAbuseReport(false);

    const snapshot = metrics.snapshot();
    expect(snapshot.scope).toBe("current_process");
    expect(Object.keys(snapshot.providers)).toEqual(["gmail", "icloud", "outlook", "yahoo", "imap"]);
    expect(snapshot.providers.gmail).toMatchObject({
      scans: { started: 1, completed: 1, failed: 0, stopped: 0 },
      messages: { examined: 5, safe: 2, review: 1, highRisk: 1, unknown: 1, malformed: 1 },
      operations: {
        connect: { attempts: 1, succeeded: 1, failed: 0, active: 0, durationMilliseconds: 25 },
        fetch_page: { attempts: 1, succeeded: 0, failed: 1, active: 0, durationMilliseconds: 5 },
        list_folders: { attempts: 1, cancelled: 1, active: 0 },
      },
    });
    expect(snapshot.review).toEqual({ falsePositiveApprovals: 1, abuseReportsAccepted: 1, abuseReportsFailed: 1 });
    expect(JSON.stringify(snapshot)).not.toContain("exception");
  });

  it("merges only fixed-cardinality Worker operation aggregates and ignores labels, content and active gauges", () => {
    const metrics = new LocalOperationalMetrics(() => 5_000);
    metrics.mergeWorkerAdapterSnapshot({
      schemaVersion: 1,
      providers: {
        gmail: {
          operations: {
            move_to_trash: {
              attempts: 2,
              succeeded: 1,
              failed: 1,
              cancelled: 0,
              active: 99,
              durationMilliseconds: 17,
              rawUrl: "https://private.example.test/path",
              subject: "private subject",
            },
          },
        },
        attacker_defined_provider: {
          operations: {
            move_to_trash: { attempts: 999, succeeded: 999 },
          },
        },
      },
      mailboxAddress: "private@example.test",
    });

    const snapshot = metrics.snapshot();
    expect(snapshot.providers.gmail.operations.move_to_trash).toEqual({
      attempts: 2,
      succeeded: 1,
      failed: 1,
      cancelled: 0,
      active: 0,
      durationMilliseconds: 17,
    });
    expect(Object.keys(snapshot.providers)).toEqual(["gmail", "icloud", "outlook", "yahoo", "imap"]);
    const serialized = JSON.stringify(snapshot);
    expect(serialized).not.toContain("attacker_defined_provider");
    expect(serialized).not.toContain("private.example.test");
    expect(serialized).not.toContain("private subject");
    expect(serialized).not.toContain("private@example.test");
  });
});
