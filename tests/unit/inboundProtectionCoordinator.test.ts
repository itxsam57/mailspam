import { describe, expect, it } from "vitest";
import {
  InMemoryInboundEventStateRepository,
  InboundEventBacklogError,
  InboundProtectionCoordinator,
  InvalidInboundEventError,
  type CanonicalInboundEventV1,
} from "../../server/src/realtime/inboundEvents.js";

function event(overrides: Partial<CanonicalInboundEventV1> = {}): CanonicalInboundEventV1 {
  return {
    schemaVersion: 1,
    accountKey: "account-local-key",
    provider: "gmail",
    source: "push",
    kind: "mailbox_changed",
    eventId: "history-42",
    checkpoint: "42",
    providerMessageId: null,
    ...overrides,
  };
}

describe("InboundProtectionCoordinator", () => {
  it("processes one canonical event and remembers only a hashed replay key", async () => {
    const repository = new InMemoryInboundEventStateRepository();
    let processed = 0;
    const coordinator = new InboundProtectionCoordinator({
      repository,
      processor: async () => {
        processed += 1;
        return { examined: 3, warnings: 1, highRisk: 1, confirmedThreat: 0 };
      },
    });

    const outcome = await coordinator.enqueue(event());
    expect(outcome).toEqual({
      status: "processed",
      result: { examined: 3, warnings: 1, highRisk: 1, confirmedThreat: 0 },
    });
    expect(processed).toBe(1);
    const stored = repository.load();
    expect(stored.rememberedEventKeys).toHaveLength(1);
    expect(stored.rememberedEventKeys[0]).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(stored)).not.toContain("history-42");
    expect(coordinator.checkpoint("account-local-key", "gmail", "push")).toBe("42");
  });

  it("deduplicates replay after coordinator restart", async () => {
    const repository = new InMemoryInboundEventStateRepository();
    let processed = 0;
    const makeCoordinator = () => new InboundProtectionCoordinator({
      repository,
      processor: async () => {
        processed += 1;
        return { examined: 1, warnings: 0, highRisk: 0, confirmedThreat: 0 };
      },
    });

    expect((await makeCoordinator().enqueue(event())).status).toBe("processed");
    expect((await makeCoordinator().enqueue(event())).status).toBe("duplicate");
    expect(processed).toBe(1);
  });

  it("coalesces concurrent duplicate deliveries instead of scanning twice", async () => {
    const repository = new InMemoryInboundEventStateRepository();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    let processed = 0;
    const coordinator = new InboundProtectionCoordinator({
      repository,
      processor: async () => {
        processed += 1;
        await gate;
        return { examined: 2, warnings: 1, highRisk: 0, confirmedThreat: 0 };
      },
    });

    const first = coordinator.enqueue(event());
    const second = coordinator.enqueue(event());
    release();
    expect((await first).status).toBe("processed");
    const secondOutcome = await second;
    expect(secondOutcome.status).toBe("coalesced");
    expect(processed).toBe(1);
  });

  it("does not acknowledge or checkpoint failed processing so the event can retry", async () => {
    const repository = new InMemoryInboundEventStateRepository();
    let attempts = 0;
    const coordinator = new InboundProtectionCoordinator({
      repository,
      processor: async () => {
        attempts += 1;
        if (attempts === 1) throw new Error("temporary provider failure");
        return { examined: 1, warnings: 0, highRisk: 0, confirmedThreat: 0 };
      },
    });

    await expect(coordinator.enqueue(event())).rejects.toThrow("temporary provider failure");
    expect(repository.load().rememberedEventKeys).toHaveLength(0);
    expect(coordinator.checkpoint("account-local-key", "gmail", "push")).toBeNull();
    expect((await coordinator.enqueue(event())).status).toBe("processed");
    expect(attempts).toBe(2);
  });

  it("fails closed when the bounded real-time backlog is full", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const coordinator = new InboundProtectionCoordinator({
      repository: new InMemoryInboundEventStateRepository(),
      maxPending: 1,
      processor: async () => {
        await gate;
        return { examined: 1, warnings: 0, highRisk: 0, confirmedThreat: 0 };
      },
    });

    const first = coordinator.enqueue(event());
    await expect(coordinator.enqueue(event({ eventId: "history-43", checkpoint: "43" })))
      .rejects.toBeInstanceOf(InboundEventBacklogError);
    release();
    await first;
  });

  it("rejects unknown fields, unsupported providers and oversized identifiers", async () => {
    const coordinator = new InboundProtectionCoordinator({
      repository: new InMemoryInboundEventStateRepository(),
      processor: async () => ({ examined: 0, warnings: 0, highRisk: 0, confirmedThreat: 0 }),
    });

    await expect(coordinator.enqueue({ ...event(), secret: "must-not-pass" }))
      .rejects.toBeInstanceOf(InvalidInboundEventError);
    await expect(coordinator.enqueue({ ...event(), provider: "other" }))
      .rejects.toBeInstanceOf(InvalidInboundEventError);
    await expect(coordinator.enqueue({ ...event(), eventId: "x".repeat(5000) }))
      .rejects.toBeInstanceOf(InvalidInboundEventError);
  });

  it("rejects inconsistent processor counters instead of persisting a false success", async () => {
    const repository = new InMemoryInboundEventStateRepository();
    const coordinator = new InboundProtectionCoordinator({
      repository,
      processor: async () => ({ examined: 1, warnings: 1, highRisk: 1, confirmedThreat: 0 }),
    });

    await expect(coordinator.enqueue(event())).rejects.toBeInstanceOf(InvalidInboundEventError);
    expect(repository.load().rememberedEventKeys).toHaveLength(0);
  });
});
