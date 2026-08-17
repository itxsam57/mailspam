import { describe, expect, it } from "vitest";
import {
  BackgroundProtectionCoordinator,
  BackgroundProtectionRunError,
  nextBackgroundRunAt,
  type BackgroundProtectionExecutor,
} from "../../server/src/api/backgroundProtection.js";
import { InMemoryBackgroundProtectionRepository } from "../../server/src/api/backgroundProtectionPersistence.js";
import type { AccountSession } from "../../server/src/api/sessionStore.js";

function session(accountKey: string, activeScanWorker: AccountSession["activeScanWorker"] = null): AccountSession {
  return {
    id: `session-${accountKey.slice(0, 8)}`,
    provider: "gmail",
    label: "fixture",
    config: { provider: "gmail", mode: "fixture", fixtureFolderOverrides: {} },
    activeScanWorker,
    personalPolicy: {} as AccountSession["personalPolicy"],
    policyAccountKey: accountKey,
    vaultReferences: [],
    closing: false,
    unsubscribeActions: new Map(),
    reviewActions: new Map(),
  };
}

describe("quota-aware background protection coordinator", () => {
  it("honors the configured interval from first enable, then executes and resets a successful run", async () => {
    let now = 1_800_000_000_000;
    const repository = new InMemoryBackgroundProtectionRepository();
    const account = session("1".repeat(64));
    let executions = 0;
    const executor: BackgroundProtectionExecutor = { execute: async () => { executions++; now += 2_000; } };
    const coordinator = new BackgroundProtectionCoordinator({
      repository,
      sessions: { list: () => [account] },
      executor,
      now: () => now,
    });

    const configured = coordinator.configure(account.policyAccountKey, true, 60, now);
    expect(configured.nextRunAt).toBe(now + 60 * 60_000);
    expect(await coordinator.runDue(now + 60_000)).toBe(false);
    expect(executions).toBe(0);
    expect(await coordinator.runDue(now + 60 * 60_000)).toBe(true);
    expect(executions).toBe(1);
    expect(coordinator.status(account.policyAccountKey)).toMatchObject({
      status: "completed",
      consecutiveFailures: 0,
      lastErrorCode: null,
      active: false,
    });
  });

  it("defers disconnected and manually scanning accounts without inflating failures", async () => {
    const now = 1_800_000_000_000;
    const repository = new InMemoryBackgroundProtectionRepository();
    const accountKey = "2".repeat(64);
    const coordinator = new BackgroundProtectionCoordinator({
      repository,
      sessions: { list: () => [] },
      executor: { execute: async () => { throw new Error("must not run"); } },
      now: () => now,
    });
    coordinator.configure(accountKey, true, 30, now - 30 * 60_000);
    expect(await coordinator.runDue(now)).toBe(false);
    expect(repository.get(accountKey)).toMatchObject({
      status: "deferred",
      lastErrorCode: "provider_unavailable",
      consecutiveFailures: 0,
      nextRunAt: now + 5 * 60_000,
    });

    const active = session(accountKey, {} as AccountSession["activeScanWorker"]);
    repository.save(accountKey, { ...repository.get(accountKey)!, nextRunAt: now });
    const conflicted = new BackgroundProtectionCoordinator({
      repository,
      sessions: { list: () => [active] },
      executor: { execute: async () => { throw new Error("must not run"); } },
      now: () => now,
    });
    expect(await conflicted.runDue(now)).toBe(false);
    expect(repository.get(accountKey)?.lastErrorCode).toBe("scan_conflict");
  });

  it("allows only one global run and applies bounded failure backoff", async () => {
    const now = 1_800_000_000_000;
    const repository = new InMemoryBackgroundProtectionRepository();
    const first = session("3".repeat(64));
    const second = session("4".repeat(64));
    let release!: () => void;
    const pending = new Promise<void>((resolve) => { release = resolve; });
    const executor: BackgroundProtectionExecutor = { execute: async (value) => {
      if (value === first) await pending;
      else throw new BackgroundProtectionRunError("resource_deadline", "bounded deadline");
    } };
    const coordinator = new BackgroundProtectionCoordinator({
      repository,
      sessions: { list: () => [first, second] },
      executor,
      now: () => now,
    });
    coordinator.configure(first.policyAccountKey, true, 30, now - 30 * 60_000);
    coordinator.configure(second.policyAccountKey, true, 30, now - 30 * 60_000);
    const firstRun = coordinator.runDue(now);
    expect(await coordinator.runDue(now)).toBe(false);
    release();
    expect(await firstRun).toBe(true);

    expect(await coordinator.runDue(now)).toBe(true);
    expect(repository.get(second.policyAccountKey)).toMatchObject({
      status: "failed",
      lastErrorCode: "resource_deadline",
      consecutiveFailures: 1,
      nextRunAt: nextBackgroundRunAt(now, 30, 1),
    });
  });

  it("pauses cleanly and never resurrects a removed schedule after an active run", async () => {
    const now = 1_800_000_000_000;
    const repository = new InMemoryBackgroundProtectionRepository();
    const account = session("5".repeat(64));
    let release!: () => void;
    const pending = new Promise<void>((resolve) => { release = resolve; });
    const coordinator = new BackgroundProtectionCoordinator({
      repository,
      sessions: { list: () => [account] },
      executor: { execute: async () => pending },
      now: () => now,
    });
    const paused = coordinator.configure(account.policyAccountKey, false, 60, now);
    expect(paused).toMatchObject({ enabled: false, status: "paused", nextRunAt: null });
    coordinator.configure(account.policyAccountKey, true, 60, now - 60 * 60_000);
    const run = coordinator.runDue(now);
    coordinator.remove(account.policyAccountKey);
    release();
    await run;
    expect(repository.get(account.policyAccountKey)).toBeNull();
  });
});
