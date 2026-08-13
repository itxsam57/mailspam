import { parentPort, workerData } from "node:worker_threads";
import { createAdapter, type AdapterConfig } from "../api/adapterConfig.js";
import type { SecureAdapterConfig } from "../security/secureAdapterConfig.js";
import {
  quickScan,
  fullMailboxAudit,
  spamJunkScan,
  type ScanDiagnosticSummary,
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
import type { ConsumerMailboxRule } from "../api/consumerStatePersistence.js";
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
  consumerRules?: ConsumerMailboxRule[];
}

const data = workerData as WorkData;
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

function activeConsumerRules(): ConsumerMailboxRule[] {
  const now = Date.now();
  return (data.consumerRules ?? []).filter((rule) =>
    rule.enabled === true && (rule.expiresAt === null || rule.expiresAt > now),
  );
}

function ruleMatchesSummary(rule: ConsumerMailboxRule, summary: ScanDiagnosticSummary): boolean {
  const senderAddress = summary.actionContext.senderAddress?.trim().toLowerCase() ?? "";
  const senderDomain = summary.fromDomain?.trim().toLowerCase() ?? "";
  if (rule.senderAddress && senderAddress !== rule.senderAddress) return false;
  if (rule.senderDomain && senderDomain !== rule.senderDomain) return false;
  return Boolean(rule.senderAddress || rule.senderDomain);
}

function collectConsumerRuleActions(
  summaries: readonly ScanDiagnosticSummary[],
  trashIds: Set<string>,
): { catchTrash: number; screened: number } {
  const rules = activeConsumerRules();
  let catchTrash = 0;
  let screened = 0;
  for (const summary of summaries) {
    for (const rule of rules) {
      if (rule.type === "trash_after_unsubscribe" && ruleMatchesSummary(rule, summary)) {
        if (!trashIds.has(summary.actionContext.providerNativeId)) catchTrash += 1;
        trashIds.add(summary.actionContext.providerNativeId);
      }
      if (rule.type === "screen_first_contact" && summary.firstContact === true) screened += 1;
    }
  }
  return { catchTrash, screened };
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
      message: `Applying Email Shield protection: ${trashIds.size} confirmed/explicit-rule message(s) to Trash, ${quarantineIds.size} signed-warning message(s) to Spam/Junk…`,
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
  const pageSize = data.pageSize ?? 20;
  const generator = data.type === "quick"
    ? quickScan(adapter, deps, controller.signal, pageSize, data.maxMessages ?? pageSize, data.resume)
    : data.type === "spam"
      ? spamJunkScan(adapter, deps, controller.signal, pageSize, data.resume)
      : fullMailboxAudit(adapter, deps, controller.signal, { pageSize, resume: data.resume });

  let emittedProgress = false;
  const autoTrashIds = new Set<string>();
  const warningQuarantineIds = new Set<string>();
  let consumerCatchTrash = 0;
  let screened = 0;
  for await (const progress of generator) {
    emittedProgress = true;
    onProgress();
    collectDurableAutoTrashIds(progress.suspiciousCards, autoTrashIds);
    collectCommunityWarningQuarantineIds(progress.suspiciousCards, warningQuarantineIds);
    const consumerActions = collectConsumerRuleActions(progress.diagnosticSummaries, autoTrashIds);
    consumerCatchTrash += consumerActions.catchTrash;
    screened += consumerActions.screened;
    parentPort?.postMessage({ type: "progress", progress });
  }

  if (consumerCatchTrash || screened) {
    parentPort?.postMessage({
      type: "consumer-rule-summary",
      summary: { catchTrash: consumerCatchTrash, screened },
    });
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
      ? { phase: "complete", message: "Scan completed and signed/durable protection actions were enforced." }
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
