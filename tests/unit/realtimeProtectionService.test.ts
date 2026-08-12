import { describe, expect, it } from "vitest";
import type { AccountSession } from "../../server/src/api/sessionStore.js";
import { InMemoryInboundEventStateRepository } from "../../server/src/realtime/inboundEvents.js";
import {
  MIN_REALTIME_POLL_INTERVAL_MS,
  RealtimeProtectionService,
} from "../../server/src/realtime/realtimeProtectionService.js";

function session(accountKey: string, provider: "gmail" | "outlook" = "gmail"): AccountSession {
  return {
    id: `session-${accountKey.slice(0, 4)}-${provider}`,
    provider,
    label: "fixture",
    config: provider === "gmail"
      ? { provider: "gmail", mode: "fixture", fixtureFolderOverrides: {} }
      : { provider: "outlook", mode: "fixture", fixtureFolderOverrides: {} },
    activeScanWorker: null,
    personalPolicy: {} as AccountSession["personalPolicy"],
    policyAccountKey: accountKey,
    vaultReferences: [],
    closing: false,
    unsubscribeActions: new Map(),
    reviewActions: new Map(),
  };
}

describe("RealtimeProtectionService", () => {
  it("polls connected accounts through one serial inbound coordinator", async () => {
    const sessions = [session("a".repeat(64)), session("b".repeat(64), "outlook")];
    let active = 0;
    let maxActive = 0;
    const processed: string[] = [];
    const service = new RealtimeProtectionService({
      sessions: { list: () => sessions },
      repository: new InMemoryInboundEventStateRepository(),
      pollIntervalMs: MIN_REALTIME_POLL_INTERVAL_MS,
      processor: {
        process: async (event) => {
          active += 1;
          maxActive = Math.max(maxActive, active);
          processed.push(`${event.accountKey}:${event.provider}:${event.source}`);
          await new Promise((resolve) => setTimeout(resolve, 1));
          active -= 1;
          return { examined: 1, warnings: 0, highRisk: 0, confirmedThreat: 0 };
        },
      },
    });

    await service.pollNow(1_000);
    expect(processed).toEqual([
      `${"a".repeat(64)}:gmail:poll`,
      `${"b".repeat(64)}:outlook:poll`,
    ]);
    expect(maxActive).toBe(1);
    expect(service.status()).toMatchObject({
      running: false,
      persistentReplayState: false,
      connectedAccounts: 2,
      lastPollAt: 1_000,
    });
  });

  it("retries the exact opaque poll event after processing failure and advances only after success", async () => {
    const ids: string[] = [];
    let attempts = 0;
    const service = new RealtimeProtectionService({
      sessions: { list: () => [session("c".repeat(64))] },
      repository: new InMemoryInboundEventStateRepository(),
      processor: {
        process: async (event) => {
          ids.push(event.eventId);
          attempts += 1;
          if (attempts === 1) {
            const error = new Error("temporary conflict") as Error & { code: string };
            error.code = "scan_conflict";
            throw error;
          }
          return { examined: 1, warnings: 0, highRisk: 0, confirmedThreat: 0 };
        },
      },
    });

    await service.pollNow(2_000);
    expect(service.status().lastErrorCode).toBe("scan_conflict");
    await service.pollNow(3_000);
    expect(ids[1]).toBe(ids[0]);
    expect(service.status().lastErrorCode).toBeNull();
    await service.pollNow(4_000);
    expect(ids[2]).not.toBe(ids[1]);
  });

  it("does not let one unavailable mailbox starve another connected account", async () => {
    const bad = "d".repeat(64);
    const good = "e".repeat(64);
    const processed: string[] = [];
    const service = new RealtimeProtectionService({
      sessions: { list: () => [session(bad), session(good)] },
      repository: new InMemoryInboundEventStateRepository(),
      processor: {
        process: async (event) => {
          processed.push(event.accountKey);
          if (event.accountKey === bad) throw new Error("provider unavailable");
          return { examined: 2, warnings: 1, highRisk: 0, confirmedThreat: 0 };
        },
      },
    });

    await service.pollNow();
    expect(processed).toEqual([bad, good]);
    expect(service.status().lastSuccessAt).not.toBeNull();
  });

  it("coalesces overlapping poll ticks instead of creating duplicate scans", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let calls = 0;
    const service = new RealtimeProtectionService({
      sessions: { list: () => [session("f".repeat(64))] },
      repository: new InMemoryInboundEventStateRepository(),
      processor: {
        process: async () => {
          calls += 1;
          await gate;
          return { examined: 1, warnings: 0, highRisk: 0, confirmedThreat: 0 };
        },
      },
    });

    const first = service.pollNow();
    await service.pollNow();
    expect(calls).toBe(1);
    release();
    await first;
  });

  it("rejects polling cadences that would create an abusive or useless runtime", () => {
    expect(() => new RealtimeProtectionService({
      sessions: { list: () => [] },
      repository: new InMemoryInboundEventStateRepository(),
      processor: { process: async () => ({ examined: 0, warnings: 0, highRisk: 0, confirmedThreat: 0 }) },
      pollIntervalMs: 1_000,
    })).toThrow(/polling interval/i);
  });

  it("accepts immediate push/idle events through the same replay-safe coordinator", async () => {
    let calls = 0;
    const service = new RealtimeProtectionService({
      sessions: { list: () => [] },
      repository: new InMemoryInboundEventStateRepository(),
      processor: {
        process: async () => {
          calls += 1;
          return { examined: 1, warnings: 0, highRisk: 1, confirmedThreat: 0 };
        },
      },
    });
    const event = {
      schemaVersion: 1 as const,
      accountKey: "g".repeat(64),
      provider: "gmail" as const,
      source: "push" as const,
      kind: "mailbox_changed" as const,
      eventId: "pubsub-1",
      checkpoint: "99",
      providerMessageId: null,
    };
    expect((await service.enqueue(event)).status).toBe("processed");
    expect((await service.enqueue(event)).status).toBe("duplicate");
    expect(calls).toBe(1);
  });
});
