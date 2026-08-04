import { parentPort, workerData } from "node:worker_threads";
import { createAdapter, type AdapterConfig } from "../api/adapterConfig.js";
import { quickScan, fullMailboxAudit, spamJunkScan } from "../workflows/scanWorkflows.js";
import { InMemoryPersonalPolicyStore } from "../engine/layers/personalRules.js";

interface WorkData {
  config: AdapterConfig;
  type: "quick" | "full" | "spam";
  pageSize?: number;
  personalPolicy?: { blockedSenders?: string[]; blockedDomains?: string[]; trustedSenders?: string[]; approvedExceptions?: string[] };
}
const data = workerData as WorkData;
const controller = new AbortController();
parentPort?.on("message", (message) => { if (message?.type === "cancel") controller.abort(); });

async function main() {
  const adapter = createAdapter(data.config);
  const personalPolicy = new InMemoryPersonalPolicyStore();
  personalPolicy.restore(data.personalPolicy ?? {});
  const deps = {
    personalPolicy,
    threatFeed: { getVerifiedEntries: () => [] },
  };
  const generator = data.type === "quick"
    ? quickScan(adapter, deps, controller.signal, data.pageSize ?? 20)
    : data.type === "spam"
      ? spamJunkScan(adapter, deps, controller.signal, data.pageSize ?? 20)
      : fullMailboxAudit(adapter, deps, controller.signal, { pageSize: data.pageSize ?? 20 });
  for await (const progress of generator) parentPort?.postMessage({ type: "progress", progress });
  parentPort?.postMessage({ type: "complete" });
}

main().catch((error: Error) => {
  parentPort?.postMessage({ type: "error", message: error.message, name: error.name });
});
