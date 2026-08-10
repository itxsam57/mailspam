import { strict as assert } from "node:assert";
import {
  BackgroundProtectionCoordinator,
  WorkerBackgroundProtectionExecutor,
} from "../../server/dist/api/backgroundProtection.js";
import { InMemoryBackgroundProtectionRepository } from "../../server/dist/api/backgroundProtectionPersistence.js";
import { defaultScanStateRepository } from "../../server/dist/api/defaultScanStateRepository.js";
import { sessionStore } from "../../server/dist/api/sessionStore.js";

const community = {
  remoteUrl: "",
  getVerifiedEntries: () => [],
  refreshFeed: async () => ({ refreshed: false }),
};
const repository = new InMemoryBackgroundProtectionRepository();
const coordinator = new BackgroundProtectionCoordinator({
  repository,
  sessions: sessionStore,
  executor: new WorkerBackgroundProtectionExecutor(community),
});
const session = sessionStore.create("gmail", "background-smoke", { provider: "gmail", mode: "fixture" });

try {
  const now = Date.now();
  coordinator.configure(session.policyAccountKey, true, 30, now - 120_000);
  assert.equal(await coordinator.runDue(now), true, "A due background scan must execute.");
  const status = coordinator.status(session.policyAccountKey);
  assert.equal(status.status, "completed");
  assert.equal(status.consecutiveFailures, 0);
  assert.equal(status.lastErrorCode, null);
  assert.equal(status.active, false);
  assert.ok(Number.isSafeInteger(status.nextRunAt) && status.nextRunAt > now);

  const history = defaultScanStateRepository.list(session.policyAccountKey);
  const completed = history.find((record) => record.type === "quick" && record.status === "completed");
  assert.ok(completed, "The background run must create completed protected scan history.");
  assert.ok(completed.counters.examined > 0 && completed.counters.examined <= 20);
  assert.equal(completed.checkpoint, null);
  console.log(`Compiled background-protection smoke passed; examined ${completed.counters.examined} bounded fixture messages.`);
} finally {
  coordinator.remove(session.policyAccountKey);
  await sessionStore.remove(session.id);
}
