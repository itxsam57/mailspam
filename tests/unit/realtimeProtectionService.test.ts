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
  it("treats fallback polling as idle housekeeping and never fabricates mailbox-change scans", async () => {
    const sessions = [session("a".repeat(64)), session("b".repeat(64), "outlook")];
    const processed: string[] = [];
    const service = new RealtimeProtectionService({
      sessions: { list: () => sessions },
      repository: new InMemoryInboundEventStateRepository(),
      pollIntervalMs: MIN_REALTIME_POLL_INTERVAL_MS,
      processor: {
        process: async (event) => {
          processed.push(`${event.accountKey}:${event.provider}:${event.source}`);
          return { examined: 1, warnings: 0, highRisk: 0, confirmedThreat: 0 };
        },
      },
    });

    await service.pollNow(1_000);
    await service.pollNow(2_000);
    expect(processed).toEqual([]);
    expect(service.status()).toMatchObject({
      running: false,
      persistentReplayState: false,
      connectedAccounts: 2,
      lastPollAt: 2_000,
      lastSuccessAt: null,
      lastErrorAt: null,
      lastErrorCode: null,
    });
  });

  it("does not turn an immediate startup poll into a Quick scan on an idle connected account", async () => {
    let calls = 0;
    const service = new RealtimeProtectionService({
      sessions: { list: () => [session("c".repeat(64))] },
      repository: new InMemoryInboundEventStateRepository(),
      pollIntervalMs: MIN_REALTIME_POLL_INTERVAL_MS,
      processor: {
        process: async () => {
          calls += 1;
          return { examined: 1, warnings: 0, highRisk: 0, confirmedThreat: 0 };
        },
      },
    });

    service.start();
    await new Promise((resolve) => setTimeout(resolve, 5));
    service.stop();
    expect(calls).toBe(0);
    expect(service.status().lastPollAt).not.toBeNull();
  });

  it("rejects polling cadences that would create an abusive or useless runtime", () => {
    expect(() => new RealtimeProtectionService({
      sessions: { list: () => [] },
      repository: new InMemoryInboundEventStateRepository(),
      processor: { process: async () => ({ examined: 0, warnings: 0, highRisk: 0, confirmedThreat: 0 }) },
      pollIntervalMs: 1_000,
    })).toThrow(/polling interval/i);
  });

  it("accepts genuine push/idle events through the same replay-safe coordinator", async () => {
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
