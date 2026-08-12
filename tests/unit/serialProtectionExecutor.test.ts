import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { AccountSession } from "../../server/src/api/sessionStore.js";
import { BackgroundProtectionRunError } from "../../server/src/api/backgroundProtection.js";
import { SerialProtectionExecutor } from "../../server/src/realtime/serialProtectionExecutor.js";

function session(key: string): AccountSession {
  return {
    id: `session-${key.slice(0, 3)}`,
    provider: "gmail",
    label: "fixture",
    config: { provider: "gmail", mode: "fixture", fixtureFolderOverrides: {} },
    activeScanWorker: null,
    personalPolicy: {} as AccountSession["personalPolicy"],
    policyAccountKey: key,
    vaultReferences: [],
    closing: false,
    unsubscribeActions: new Map(),
    reviewActions: new Map(),
  };
}

const counters = {
  examined: 1,
  safe: 1,
  review: 0,
  highRisk: 0,
  confirmedThreat: 0,
  unknown: 0,
};

describe("SerialProtectionExecutor", () => {
  it("fails fast instead of queuing a second scheduled/realtime Worker scan", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let calls = 0;
    const executor = new SerialProtectionExecutor({
      executeWithSummary: async () => {
        calls += 1;
        await gate;
        return counters;
      },
    });

    const first = executor.executeWithSummary(session("a".repeat(64)));
    expect(executor.activeAccountKey).toBe("a".repeat(64));
    await expect(executor.executeWithSummary(session("b".repeat(64))))
      .rejects.toBeInstanceOf(BackgroundProtectionRunError);
    expect(calls).toBe(1);
    release();
    await expect(first).resolves.toEqual(counters);
    expect(executor.activeAccountKey).toBeNull();
  });

  it("releases the shared slot after an underlying Worker failure", async () => {
    let fail = true;
    const executor = new SerialProtectionExecutor({
      executeWithSummary: async () => {
        if (fail) throw new Error("worker failed");
        return counters;
      },
    });
    await expect(executor.executeWithSummary(session("c".repeat(64)))).rejects.toThrow("worker failed");
    expect(executor.activeAccountKey).toBeNull();
    fail = false;
    await expect(executor.executeWithSummary(session("d".repeat(64)))).resolves.toEqual(counters);
  });

  it("uses the same serial executor for scheduled and realtime runtime composition", () => {
    const source = readFileSync(new URL("../../server/src/index.ts", import.meta.url), "utf8");
    expect(source).toContain("const protectionExecutor = new SerialProtectionExecutor(workerProtectionExecutor)");
    expect(source).toContain("executor: protectionExecutor");
    expect(source).toContain("new RealtimeProtectionProcessor(sessionStore, protectionExecutor)");
    expect(source).toContain("createDefaultInboundEventStateRepository");
    expect(source).toContain("realtimeProtection.start()");
  });
});
