import { describe, expect, it } from "vitest";
import { ActiveScanLifecycle } from "../../server/src/api/scanLifecycle.js";

const counters = {
  examined: 40,
  safe: 30,
  review: 4,
  highRisk: 2,
  confirmedThreat: 1,
  unknown: 3,
  skipped: 0,
  malformed: 0,
};

describe("active scan lifecycle", () => {
  it("does not resolve a stop wait until the scan owner finalizes the exact active scan", async () => {
    const lifecycle = new ActiveScanLifecycle();
    lifecycle.begin("session-1", "scan-1");
    expect(lifecycle.requestStop("session-1")).toBe(true);
    expect(lifecycle.stopRequested("session-1", "scan-1")).toBe(true);

    const wait = lifecycle.wait("session-1");
    expect(wait).not.toBeNull();
    let resolved = false;
    void wait!.then(() => { resolved = true; });
    await Promise.resolve();
    expect(resolved).toBe(false);

    expect(lifecycle.finalize("session-1", "other-scan", {
      scanId: "other-scan",
      status: "stopped",
      historySaved: true,
      resumable: true,
      counters,
    })).toBe(false);
    await Promise.resolve();
    expect(resolved).toBe(false);

    expect(lifecycle.finalize("session-1", "scan-1", {
      scanId: "scan-1",
      status: "stopped",
      historySaved: true,
      resumable: true,
      counters,
    })).toBe(true);
    await expect(wait).resolves.toEqual({
      scanId: "scan-1",
      status: "stopped",
      historySaved: true,
      resumable: true,
      counters,
    });
    expect(lifecycle.has("session-1")).toBe(false);
  });

  it("keeps mailbox lifecycles isolated and refuses a second active owner", async () => {
    const lifecycle = new ActiveScanLifecycle();
    lifecycle.begin("session-a", "scan-a");
    lifecycle.begin("session-b", "scan-b");
    expect(() => lifecycle.begin("session-a", "scan-c")).toThrow(/already active/i);
    expect(lifecycle.requestStop("missing")).toBe(false);
    expect(lifecycle.requestStop("session-a")).toBe(true);
    expect(lifecycle.stopRequested("session-b")).toBe(false);

    const waitA = lifecycle.wait("session-a")!;
    lifecycle.finalize("session-a", "scan-a", {
      scanId: "scan-a", status: "stopped", historySaved: true, resumable: true, counters,
    });
    await expect(waitA).resolves.toMatchObject({ scanId: "scan-a", status: "stopped" });
    expect(lifecycle.has("session-b")).toBe(true);
  });
});