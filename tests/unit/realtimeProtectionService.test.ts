import { describe, expect, it } from "vitest";
import type { AccountSession } from "../../server/src/api/sessionStore.js";
import { InMemoryInboundEventStateRepository } from "../../server/src/realtime/inboundEvents.js";
import {
  MIN_REALTIME_POLL_INTERVAL_MS,
  RealtimeProtectionService,
} from "../../server/src/realtime/realtimeProtectionService.js";

function session(
  accountKey: string,
  provider: "gmail" | "outlook" | "icloud" | "yahoo" | "imap" = "gmail",
): AccountSession {
  return {
    id: `session-${accountKey.slice(0, 4)}-${provider}`,
    provider,
    label: "fixture",
    config: { provider, mode: "fixture", fixtureFolderOverrides: {} },
    activeScanWorker: null,
    personalPolicy: {} as AccountSession["personalPolicy"],
    policyAccountKey: accountKey,
    vaultReferences: [],
    closing: false,
    unsubscribeActions: new Map(),
    reviewActions: new Map(),
  } as AccountSession;
}

function createService(options: Record<string, unknown>): RealtimeProtectionService {
  // Intentionally pass through an untyped boundary so this RED test can define
  // the desired probe contract before production accepts the new dependency.
  return new RealtimeProtectionService(options as never);
}

describe("RealtimeProtectionService", () => {
  it("uses trusted metadata checkpoints so baseline and unchanged polls do not scan, but a real change does", async () => {
    const account = session("a".repeat(64));
    let checkpoint = "checkpoint-1";
    const processed: Array<{ eventId: string; source: string; checkpoint: string | null | undefined }> = [];
    const service = createService({
      sessions: { list: () => [account] },
      repository: new InMemoryInboundEventStateRepository(),
      pollIntervalMs: MIN_REALTIME_POLL_INTERVAL_MS,
      pollProbe: { checkpoint: async () => checkpoint },
      processor: {
        process: async (event: { eventId: string; source: string; checkpoint?: string | null }) => {
          processed.push({ eventId: event.eventId, source: event.source, checkpoint: event.checkpoint });
          return { examined: 1, warnings: 0, highRisk: 0, confirmedThreat: 0 };
        },
      },
    });

    await service.pollNow(1_000); // establish baseline
    await service.pollNow(2_000); // unchanged
    expect(processed).toEqual([]);

    checkpoint = "checkpoint-2";
    await service.pollNow(3_000);
    expect(processed).toHaveLength(1);
    expect(processed[0]).toMatchObject({ source: "poll", checkpoint: "checkpoint-2" });
    expect(service.status().lastSuccessAt).not.toBeNull();
  });

  it("persists the poll baseline across service restart and scans only after a later checkpoint changes", async () => {
    const account = session("h".repeat(64));
    const repository = new InMemoryInboundEventStateRepository();
    let checkpoint = "checkpoint-1";
    let processed = 0;
    const dependencies = () => ({
      sessions: { list: () => [account] },
      repository,
      pollProbe: { checkpoint: async () => checkpoint },
      processor: {
        process: async () => {
          processed += 1;
          return { examined: 1, warnings: 0, highRisk: 0, confirmedThreat: 0 };
        },
      },
    });

    const first = createService(dependencies());
    await first.pollNow(1_000);
    expect(processed).toBe(0);

    const restarted = createService(dependencies());
    await restarted.pollNow(2_000);
    expect(processed).toBe(0);

    checkpoint = "checkpoint-2";
    await restarted.pollNow(3_000);
    expect(processed).toBe(1);
  });

  it("retries the exact changed checkpoint after processing failure and advances only after success", async () => {
    const account = session("b".repeat(64));
    let checkpoint = "checkpoint-1";
    const ids: string[] = [];
    let attempts = 0;
    const service = createService({
      sessions: { list: () => [account] },
      repository: new InMemoryInboundEventStateRepository(),
      pollProbe: { checkpoint: async () => checkpoint },
      processor: {
        process: async (event: { eventId: string }) => {
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

    await service.pollNow(1_000); // baseline
    checkpoint = "checkpoint-2";
    await service.pollNow(2_000); // fails; checkpoint must not advance
    expect(service.status().lastErrorCode).toBe("scan_conflict");
    await service.pollNow(3_000); // same changed checkpoint retries
    expect(ids[1]).toBe(ids[0]);
    expect(service.status().lastErrorCode).toBeNull();

    checkpoint = "checkpoint-3";
    await service.pollNow(4_000);
    expect(ids[2]).not.toBe(ids[1]);
  });

  it("does not let one provider probe failure starve another changed connected account", async () => {
    const bad = session("c".repeat(64), "gmail");
    const good = session("d".repeat(64), "outlook");
    const checkpoints = new Map([
      [bad.policyAccountKey, "bad-1"],
      [good.policyAccountKey, "good-1"],
    ]);
    let failBad = false;
    const processed: string[] = [];
    const service = createService({
      sessions: { list: () => [bad, good] },
      repository: new InMemoryInboundEventStateRepository(),
      pollProbe: {
        checkpoint: async (value: AccountSession) => {
          if (failBad && value.policyAccountKey === bad.policyAccountKey) throw new Error("probe unavailable");
          return checkpoints.get(value.policyAccountKey) ?? null;
        },
      },
      processor: {
        process: async (event: { accountKey: string }) => {
          processed.push(event.accountKey);
          return { examined: 1, warnings: 0, highRisk: 0, confirmedThreat: 0 };
        },
      },
    });

    await service.pollNow(1_000); // baselines
    failBad = true;
    checkpoints.set(good.policyAccountKey, "good-2");
    await service.pollNow(2_000);
    expect(processed).toEqual([good.policyAccountKey]);
  });

  it("coalesces overlapping poll ticks while a metadata probe is still active", async () => {
    const account = session("e".repeat(64));
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let probes = 0;
    const service = createService({
      sessions: { list: () => [account] },
      repository: new InMemoryInboundEventStateRepository(),
      pollProbe: {
        checkpoint: async () => {
          probes += 1;
          await gate;
          return "checkpoint-1";
        },
      },
      processor: { process: async () => ({ examined: 1, warnings: 0, highRisk: 0, confirmedThreat: 0 }) },
    });

    const first = service.pollNow(1_000);
    await Promise.resolve();
    await service.pollNow(2_000);
    expect(probes).toBe(1);
    release();
    await first;
  });

  it("does not turn an immediate startup baseline probe into a Quick scan", async () => {
    let calls = 0;
    const service = createService({
      sessions: { list: () => [session("f".repeat(64))] },
      repository: new InMemoryInboundEventStateRepository(),
      pollIntervalMs: MIN_REALTIME_POLL_INTERVAL_MS,
      pollProbe: { checkpoint: async () => "checkpoint-1" },
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
