import { parentPort, workerData } from "node:worker_threads";
import { createAdapter, type AdapterConfig } from "../api/adapterConfig.js";
import type { SecureAdapterConfig } from "../security/secureAdapterConfig.js";
import {
  quickScan,
  fullMailboxAudit,
  spamJunkScan,
  type ScanProgress,
  type ScanResumeInput,
} from "../workflows/scanWorkflows.js";
import { InMemoryPersonalPolicyStore, type PersonalPolicySnapshot } from "../engine/layers/personalRules.js";
import type { SignedFeedEntry } from "../engine/layers/globalIntelligence.js";
import type { RelationshipHistoryWorkerSnapshot } from "../engine/relationshipHistory.js";
import { runWithSingleRetry } from "./retryPolicy.js";

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
const controller = new AbortController();
parentPort?.on("message", (message) => { if (message?.type === "cancel") controller.abort(); });

const DURABLE_AUTO_TRASH_EVIDENCE = new Set([
  "BLOCKED_SENDER",
  "BLOCKED_DOMAIN",
  "LOCALLY_REPORTED_SCAM_CAMPAIGN",
  "GLOBAL_CONFIRMED_MATCH",
]);

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

function durableAutoTrashIds(progress: ScanProgress): string[] {
  const ids = new Set<string>();
  for (const result of progress.suspiciousCards) {
    if (result.scored.verdict !== "confirmed_threat") continue;
    if (!result.scored.evidence.some((item) => DURABLE_AUTO_TRASH_EVIDENCE.has(item.code))) continue;
    const providerNativeId = result.envelope.providerNativeId?.trim();
    if (providerNativeId) ids.add(providerNativeId);
  }
  return [...ids];
}

async function enforceDurableAutoTrash(
  adapter: ReturnType<typeof createAdapter>,
  progress: ScanProgress,
): Promise<void> {
  const ids = durableAutoTrashIds(progress);
  if (ids.length === 0) return;

  await adapter.moveToTrash(ids, controller.signal);
  const moved = new Set(ids);
  for (const summary of progress.diagnosticSummaries) {
    if (!moved.has(summary.actionContext.providerNativeId)) continue;
    summary.decisionNotes = [
      ...summary.decisionNotes,
      "Automatically moved to Trash because a durable personal block/report or signed globally confirmed threat matched this message.",
    ];
  }
}

async function runScanAttempt(onProgress: () => void): Promise<boolean> {
  const adapter = createAdapter(data.config);
  const deps = buildDependencies();
  const pageSize = data.pageSize ?? 20;
  const generator = data.type === "quick"
    ? quickScan(adapter, deps, controller.signal, pageSize, data.maxMessages ?? pageSize, data.resume)
    : data.type === "spam"
      ? spamJunkScan(adapter, deps, controller.signal, pageSize, data.resume)
      : fullMailboxAudit(adapter, deps, controller.signal, { pageSize, resume: data.resume });

  let emittedProgress = false;
  for await (const progress of generator) {
    emittedProgress = true;
    onProgress();
    await enforceDurableAutoTrash(adapter, progress);
    parentPort?.postMessage({ type: "progress", progress });
  }
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
      message: `Reading provider messages in bounded batches of ${data.pageSize ?? 20}…`,
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
      ? { phase: "complete", message: "Scan completed." }
      : { phase: "complete", message: "Scan completed, but the selected folder contained no additional readable messages." },
  });
  parentPort?.postMessage({ type: "complete" });
}

async function run() {
  try {
    await main();
  } catch (error) {
    const err = error as Error;
    parentPort?.postMessage({ type: "error", message: err.message, name: err.name });
  } finally {
    parentPort?.close();
  }
}

void run();