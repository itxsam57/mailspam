import { parentPort, workerData } from "node:worker_threads";
import { createAdapter, type AdapterConfig } from "../api/adapterConfig.js";
import { localOperationalMetrics } from "../api/localOperationalMetrics.js";
import type { SecureAdapterConfig } from "../security/secureAdapterConfig.js";
import {
  quickScan,
  fullMailboxAudit,
  spamJunkScan,
  type ScanResumeInput,
} from "../workflows/scanWorkflows.js";
import {
  collectCommunityWarningQuarantineIds,
  collectDurableAutoTrashIds,
  enforceCommunityWarningQuarantine,
  enforceDurableAutoTrash,
} from "../workflows/durableProtection.js";
import { InMemoryPersonalPolicyStore, type PersonalPolicySnapshot } from "../engine/layers/personalRules.js";
import type { SignedFeedEntry } from "../engine/layers/globalIntelligence.js";
import type { RelationshipHistoryWorkerSnapshot } from "../engine/relationshipHistory.js";
import { runWithSingleRetry } from "./retryPolicy.js";
import { resolveScanBatchPolicy } from "./scanBatchPolicy.js";

interface WorkData {
  config: AdapterConfig | SecureAdapterConfig;
  type: "quick" | "full" | "spam";
  pageSize?: number;
  maxMessages?: number;
  resume?: ScanResumeInput;
  personalPolicy?: Partial<PersonalPolicySnapshot>;
  threatFeedEntries?: SignedFeedEntry[] | null;
  relationshipHistory?: RelationshipHistoryWorkerSnapshot;
}

const data = workerData as WorkData;
const scanBatchPolicy = resolveScanBatchPolicy(
  data.config.provider,
  data.type,
  data.pageSize,
  data.maxMessages,
);
const controller = new AbortController();
parentPort?.on("message", (message) => { if (message?.type === "cancel") controller.abort(); });

function buildDependencies() {
  const personalPolicy = new InMemoryPersonalPolicyStore();
  personalPolicy.restore(data.personalPolicy ?? {});
  const entries = data.threatFeedEntries === undefined ? [] : data.threatFeedEntries;
  return {
    personalPolicy,
    threatFeed: { getVerifiedEntries: () => entries },
    relationshipHistory: data.relationshipHistory
      ? structuredClone(data.relationshipHistory)
      : undefined,
  };
}

async function enforceCollectedProtection(
  trashIds: Set<string>,
  quarantineIds: Set<string>,
): Promise<void> {
  for (const id of trashIds) quarantineIds.delete(id);
  if (trashIds.size === 0 && quarantineIds.size === 0) return;
  if (controller.signal.aborted) throw new DOMException("Scan stopped by the user.", "AbortError");

  parentPort?.postMessage({
    type: "status",
    status: {
      phase: "enforcing_protection",
      message: `Applying Email Shield protection: ${trashIds.size} confirmed/personal-rule message(s) to Trash, ${quarantineIds.size} signed-warning message(s) to Spam/Junk…`,
    },
  });

  const adapter = createAdapter(data.config);
  try {
    await adapter.connect(controller.signal);
    if (quarantineIds.size) {
      await enforceCommunityWarningQuarantine(adapter, quarantineIds, controller.signal);
    }
    if (trashIds.size) {
      await enforceDurableAutoTrash(adapter, trashIds, controller.signal);
    }
  } finally {
    await adapter.disconnect().catch(() => undefined);
  }
}

async function runScanAttempt(onProgress: () => void): Promise<boolean> {
  const adapter = createAdapter(data.config);
  const deps = buildDependencies();
  const { pageSize, maxMessages } = scanBatchPolicy;
  const generator = data.type === "quick"
    ? quickScan(adapter, deps, controller.signal, pageSize, maxMessages ?? pageSize, data.resume)
    : data.type === "spam"
      ? spamJunkScan(adapter, deps, controller.signal, pageSize, data.resume)
      : fullMailboxAudit(adapter, deps, controller.signal, { pageSize, resume: data.resume });

  let emittedProgress = false;
  const autoTrashIds = new Set<string>();
  const warningQuarantineIds = new Set<string>();
  for await (const progress of generator) {
    emittedProgress = true;
    onProgress();
    collectDurableAutoTrashIds(progress.suspiciousCards, autoTrashIds);
    collectCommunityWarningQuarantineIds(progress.suspiciousCards, warningQuarantineIds);
    parentPort?.postMessage({ type: "progress", progress });
  }

  await enforceCollectedProtection(autoTrashIds, warningQuarantineIds);
  return emittedProgress;
}

async function main() {
  parentPort?.postMessage({
    type: "status",
    status: {
      phase: data.resume ? "resuming" : "starting",
      message: data.resume ? `Resuming ${data.type} scan worker from the last protected checkpoint…` : `Starting ${data.type} scan worker…`,
    },
  });
  parentPort?.postMessage({
    type: "status",
    status: { phase: "connecting", message: "Connecting to the mail provider and discovering folders…" },
  });
  parentPort?.postMessage({
    type: "status",
    status: {
      phase: "bounded_batches",
      message: `Reading provider messages in bounded batches of ${scanBatchPolicy.pageSize}…`,
    },
  });

  let firstAttemptHadProgress = false;
  const emittedProgress = await runWithSingleRetry(
    async (attempt) => await runScanAttempt(() => {
      if (attempt === 1) firstAttemptHadProgress = true;
    }),
    async (error) => {
      if (controller.signal.aborted) throw new DOMException("Aborted", "AbortError");
      if (firstAttemptHadProgress) throw error;
      parentPort?.postMessage({
        type: "status",
        status: {
          phase: "retrying",
          message: `${error.message}. Reconnecting and retrying the read-only scan once…`,
        },
      });
    },
  );

  if (controller.signal.aborted) throw new DOMException("Scan stopped by the user.", "AbortError");

  parentPort?.postMessage({
    type: "status",
    status: emittedProgress
      ? { phase: "complete", message: "Scan completed and signed/durable protection actions were enforced." }
      : { phase: "complete", message: "Scan completed, but the selected folder contained no additional readable messages." },
  });
}

async function run() {
  try {
    await main();
    parentPort?.postMessage({
      type: "complete",
      operationalMetrics: localOperationalMetrics.snapshot(),
    });
  } catch (error) {
    const err = error as Error;
    parentPort?.postMessage({
      type: "error",
      message: err.message,
      name: err.name,
      operationalMetrics: localOperationalMetrics.snapshot(),
    });
  } finally {
    parentPort?.close();
  }
}

void run();
