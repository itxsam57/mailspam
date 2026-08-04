import { parentPort, workerData } from "node:worker_threads";
import { createAdapter, type AdapterConfig } from "../api/adapterConfig.js";
import { quickScan, fullMailboxAudit, spamJunkScan } from "../workflows/scanWorkflows.js";
import { InMemoryPersonalPolicyStore } from "../engine/layers/personalRules.js";
import { runWithSingleRetry } from "./retryPolicy.js";

interface WorkData {
  config: AdapterConfig;
  type: "quick" | "full" | "spam";
  pageSize?: number;
  personalPolicy?: { blockedSenders?: string[]; blockedDomains?: string[]; trustedSenders?: string[]; approvedExceptions?: string[] };
}

const data = workerData as WorkData;
const controller = new AbortController();
parentPort?.on("message", (message) => { if (message?.type === "cancel") controller.abort(); });

function buildDependencies() {
  const personalPolicy = new InMemoryPersonalPolicyStore();
  personalPolicy.restore(data.personalPolicy ?? {});
  return {
    personalPolicy,
    threatFeed: { getVerifiedEntries: () => [] },
  };
}

async function runScanAttempt(): Promise<boolean> {
  const adapter = createAdapter(data.config);
  const deps = buildDependencies();
  const generator = data.type === "quick"
    ? quickScan(adapter, deps, controller.signal, data.pageSize ?? 20)
    : data.type === "spam"
      ? spamJunkScan(adapter, deps, controller.signal, data.pageSize ?? 20)
      : fullMailboxAudit(adapter, deps, controller.signal, { pageSize: data.pageSize ?? 20 });

  let emittedProgress = false;
  for await (const progress of generator) {
    emittedProgress = true;
    parentPort?.postMessage({ type: "progress", progress });
  }
  return emittedProgress;
}

async function main() {
  parentPort?.postMessage({
    type: "status",
    status: { phase: "starting", message: `Starting ${data.type} scan worker…` },
  });
  parentPort?.postMessage({
    type: "status",
    status: { phase: "connecting", message: "Connecting to the mail provider and discovering folders…" },
  });

  const emittedProgress = await runWithSingleRetry(
    async () => await runScanAttempt(),
    async (error) => {
      if (controller.signal.aborted) throw new DOMException("Aborted", "AbortError");
      parentPort?.postMessage({
        type: "status",
        status: {
          phase: "retrying",
          reset: true,
          message: `${error.message}. Reconnecting and retrying the read-only scan once…`,
        },
      });
    },
  );

  parentPort?.postMessage({
    type: "status",
    status: emittedProgress
      ? { phase: "complete", message: "Scan completed." }
      : { phase: "complete", message: "Scan completed, but the selected folder contained no readable messages." },
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
