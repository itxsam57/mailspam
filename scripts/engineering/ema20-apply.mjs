import { readFileSync, writeFileSync } from "node:fs";

function read(path) {
  return readFileSync(path, "utf8");
}

function write(path, content) {
  writeFileSync(path, content, "utf8");
}

function replaceOnce(path, before, after) {
  const source = read(path);
  const first = source.indexOf(before);
  const last = source.lastIndexOf(before);
  if (first < 0 || first !== last) {
    throw new Error(`${path}: expected exactly one guarded source block`);
  }
  write(path, source.slice(0, first) + after + source.slice(first + before.length));
}

function replaceTail(path, marker, expectedTailFragment, replacementTail) {
  const source = read(path);
  const index = source.indexOf(marker);
  if (index < 0 || index !== source.lastIndexOf(marker)) {
    throw new Error(`${path}: support tail marker is missing or ambiguous`);
  }
  const tail = source.slice(index);
  if (!tail.includes(expectedTailFragment)) {
    throw new Error(`${path}: support tail no longer matches the expected baseline`);
  }
  write(path, source.slice(0, index) + replacementTail);
}

const metricsPath = "server/src/api/localOperationalMetrics.ts";
replaceOnce(
  metricsPath,
  `export function cancelledOperationalError(error: unknown): boolean {\n  return error instanceof Error && error.name === "AbortError";\n}`,
  `function boundedWorkerMetric(value: unknown): number {\n  if (!Number.isFinite(value) || Number(value) < 0) return 0;\n  return Math.min(1_000_000_000, Math.floor(Number(value)));\n}\n\nexport function cancelledOperationalError(error: unknown): boolean {\n  return error instanceof Error && error.name === "AbortError";\n}`,
);
replaceOnce(
  metricsPath,
  `  recordFalsePositiveApproval(): void { this.falsePositiveApprovals += 1; }`,
  `  /**\n   * Worker threads own separate module instances, so adapter counters recorded\n   * inside scan/Health workers must be merged explicitly into this main-process\n   * owner. Only fixed-cardinality aggregate operation counters are accepted;\n   * active gauges, labels and content are intentionally ignored.\n   */\n  mergeWorkerAdapterSnapshot(snapshot: unknown): void {\n    if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) return;\n    const root = snapshot as { schemaVersion?: unknown; providers?: unknown };\n    if (root.schemaVersion !== 1 || !root.providers || typeof root.providers !== "object" || Array.isArray(root.providers)) return;\n    const providerRecord = root.providers as Record<string, unknown>;\n    for (const provider of PROVIDERS) {\n      const candidate = providerRecord[provider];\n      if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) continue;\n      const operations = (candidate as { operations?: unknown }).operations;\n      if (!operations || typeof operations !== "object" || Array.isArray(operations)) continue;\n      const operationRecord = operations as Record<string, unknown>;\n      for (const operation of OPERATIONS) {\n        const workerMetric = operationRecord[operation];\n        if (!workerMetric || typeof workerMetric !== "object" || Array.isArray(workerMetric)) continue;\n        const raw = workerMetric as Record<string, unknown>;\n        const metric = this.providers.get(provider)!.operations[operation];\n        metric.attempts += boundedWorkerMetric(raw.attempts);\n        metric.succeeded += boundedWorkerMetric(raw.succeeded);\n        metric.failed += boundedWorkerMetric(raw.failed);\n        metric.cancelled += boundedWorkerMetric(raw.cancelled);\n        metric.durationMilliseconds += boundedWorkerMetric(raw.durationMilliseconds);\n      }\n    }\n  }\n\n  recordFalsePositiveApproval(): void { this.falsePositiveApprovals += 1; }`,
);
replaceOnce(
  metricsPath,
  `      schemaVersion: 1 as const,\n      uptimeSeconds:`,
  `      schemaVersion: 1 as const,\n      scope: "current_process" as const,\n      uptimeSeconds:`,
);

const scanWorkerPath = "server/src/workers/scanWorker.ts";
replaceOnce(
  scanWorkerPath,
  `import { createAdapter, type AdapterConfig } from "../api/adapterConfig.js";`,
  `import { createAdapter, type AdapterConfig } from "../api/adapterConfig.js";\nimport { localOperationalMetrics } from "../api/localOperationalMetrics.js";`,
);
replaceOnce(
  scanWorkerPath,
  `  parentPort?.postMessage({ type: "complete" });\n}`,
  `}`,
);
replaceOnce(
  scanWorkerPath,
  `async function run() {\n  try {\n    await main();\n  } catch (error) {\n    const err = error as Error;\n    parentPort?.postMessage({ type: "error", message: err.message, name: err.name });\n  } finally {\n    parentPort?.close();\n  }\n}`,
  `async function run() {\n  try {\n    await main();\n    parentPort?.postMessage({\n      type: "complete",\n      operationalMetrics: localOperationalMetrics.snapshot(),\n    });\n  } catch (error) {\n    const err = error as Error;\n    parentPort?.postMessage({\n      type: "error",\n      message: err.message,\n      name: err.name,\n      operationalMetrics: localOperationalMetrics.snapshot(),\n    });\n  } finally {\n    parentPort?.close();\n  }\n}`,
);

const healthWorkerPath = "server/src/workers/consumerHealthWorker.ts";
replaceOnce(
  healthWorkerPath,
  `import { createAdapter, type AdapterConfig } from "../api/adapterConfig.js";`,
  `import { createAdapter, type AdapterConfig } from "../api/adapterConfig.js";\nimport { localOperationalMetrics } from "../api/localOperationalMetrics.js";`,
);
replaceOnce(
  healthWorkerPath,
  `async function main() {\n  const adapter = createAdapter(data.config);\n  try {\n    const result = data.mode === "cleanup" ? await cleanup(adapter) : await inspect(adapter);\n    parentPort?.postMessage({ type: "result", result });\n  } finally {\n    await adapter.disconnect().catch(() => undefined);\n  }\n}\n\nvoid main()\n  .catch((error) => parentPort?.postMessage({ type: "error", error: error instanceof Error ? error.message : String(error) }))\n  .finally(() => parentPort?.close());`,
  `async function main() {\n  const adapter = createAdapter(data.config);\n  let result: Awaited<ReturnType<typeof cleanup>> | Awaited<ReturnType<typeof inspect>>;\n  try {\n    result = data.mode === "cleanup" ? await cleanup(adapter) : await inspect(adapter);\n  } finally {\n    await adapter.disconnect().catch(() => undefined);\n  }\n  parentPort?.postMessage({\n    type: "result",\n    result,\n    operationalMetrics: localOperationalMetrics.snapshot(),\n  });\n}\n\nvoid main()\n  .catch((error) => parentPort?.postMessage({\n    type: "error",\n    error: error instanceof Error ? error.message : String(error),\n    operationalMetrics: localOperationalMetrics.snapshot(),\n  }))\n  .finally(() => parentPort?.close());`,
);

const scanStreamPath = "server/src/api/scanStream.ts";
replaceOnce(
  scanStreamPath,
  `    worker.on("message", (message) => {\n      if (finished || terminalEventSent) return;`,
  `    worker.on("message", (message) => {\n      if (message?.operationalMetrics) {\n        localOperationalMetrics.mergeWorkerAdapterSnapshot(message.operationalMetrics);\n      }\n      if (finished || terminalEventSent) return;`,
);

const backgroundPath = "server/src/api/backgroundProtection.ts";
replaceOnce(
  backgroundPath,
  `import { defaultConsumerStateRepository } from "./defaultConsumerStateRepository.js";`,
  `import { defaultConsumerStateRepository } from "./defaultConsumerStateRepository.js";\nimport { localOperationalMetrics } from "./localOperationalMetrics.js";`,
);
replaceOnce(
  backgroundPath,
  `  private readonly removedAccountKeys = new Set<string>();\n  private timer: NodeJS.Timeout | null = null;`,
  `  private readonly removedAccountKeys = new Set<string>();\n  private timer: NodeJS.Timeout | null = null;\n  private schedulerStartedAt: number | null = null;\n  private schedulerLoopCount = 0;\n  private lastSchedulerTrigger: "startup" | "interval" | "direct" | null = null;`,
);
replaceOnce(
  backgroundPath,
  `  start(): void {\n    if (this.timer) return;\n    this.repository.recoverInterrupted(this.now());\n    this.timer = setInterval(() => { void this.runDue(); }, SCHEDULER_TICK_MS);\n    this.timer.unref();\n    void this.runDue();\n  }`,
  `  start(): void {\n    if (this.timer) return;\n    this.repository.recoverInterrupted(this.now());\n    this.schedulerStartedAt = this.now();\n    this.timer = setInterval(() => { void this.runDue(this.now(), "interval"); }, SCHEDULER_TICK_MS);\n    this.timer.unref();\n    void this.runDue(this.now(), "startup");\n  }`,
);
replaceOnce(
  backgroundPath,
  `  remove(accountKey: string): void {`,
  `  diagnosticSnapshot() {\n    const entries = this.repository.list().map(({ record }) => record);\n    const statusCounts = entries.reduce<Record<string, number>>((counts, record) => {\n      counts[record.status] = (counts[record.status] ?? 0) + 1;\n      return counts;\n    }, {});\n    const errorCodeCounts = entries.reduce<Record<string, number>>((counts, record) => {\n      if (record.lastErrorCode) counts[record.lastErrorCode] = (counts[record.lastErrorCode] ?? 0) + 1;\n      return counts;\n    }, {});\n    const latest = (values: Array<number | null>) => values.reduce<number | null>((current, value) => (\n      value !== null && (current === null || value > current) ? value : current\n    ), null);\n    return {\n      schemaVersion: 1 as const,\n      scope: "current_process_scheduler_plus_persisted_schedule_state" as const,\n      schedulerRunning: this.timer !== null,\n      schedulerStartedAt: this.schedulerStartedAt,\n      schedulerLoopCount: this.schedulerLoopCount,\n      lastSchedulerTrigger: this.lastSchedulerTrigger,\n      active: this.activeAccountKey !== null,\n      repositoryPersistent: this.repository.persistent,\n      configuredAccounts: entries.length,\n      enabledAccounts: entries.filter((record) => record.enabled).length,\n      statusCounts,\n      errorCodeCounts,\n      latestAttemptAt: latest(entries.map((record) => record.lastAttemptAt)),\n      latestCompletedAt: latest(entries.map((record) => record.lastCompletedAt)),\n    };\n  }\n\n  remove(accountKey: string): void {`,
);
replaceOnce(
  backgroundPath,
  `  async runDue(now = this.now()): Promise<boolean> {\n    if (this.activeAccountKey) return false;`,
  `  async runDue(\n    now = this.now(),\n    trigger: "startup" | "interval" | "direct" = "direct",\n  ): Promise<boolean> {\n    this.schedulerLoopCount += 1;\n    this.lastSchedulerTrigger = trigger;\n    if (this.activeAccountKey) return false;`,
);
replaceOnce(
  backgroundPath,
  `  async executeWithSummary(session: AccountSession): Promise<ScanCounters> {\n    if (session.activeScanWorker) throw new BackgroundProtectionRunError("scan_conflict", "An account scan is already active.");`,
  `  async executeWithSummary(session: AccountSession): Promise<ScanCounters> {\n    const provider = session.config.provider;\n    localOperationalMetrics.recordScanStarted(provider);\n    try {\n      const counters = await this.executeWithSummaryUnmetered(session);\n      localOperationalMetrics.recordScanFinished(provider, "completed", counters);\n      return counters;\n    } catch (error) {\n      localOperationalMetrics.recordScanFinished(provider, "failed", emptyScanCounters());\n      throw error;\n    }\n  }\n\n  private async executeWithSummaryUnmetered(session: AccountSession): Promise<ScanCounters> {\n    if (session.activeScanWorker) throw new BackgroundProtectionRunError("scan_conflict", "An account scan is already active.");`,
);
replaceOnce(
  backgroundPath,
  `      worker.on("message", (message) => {\n        if (settled) return;`,
  `      worker.on("message", (message) => {\n        if (message?.operationalMetrics) {\n          localOperationalMetrics.mergeWorkerAdapterSnapshot(message.operationalMetrics);\n        }\n        if (settled) return;`,
);

const supportDiagnosticsPath = "server/src/diagnostics/supportBundleDiagnostics.ts";
write(supportDiagnosticsPath, `import type { PublicConsumerActivityRecord } from "../api/consumerStatePersistence.js";\nimport type { ScanHistoryRecord } from "../api/scanStatePersistence.js";\nimport type { RuntimeTraceCheckpointManifest } from "./checkpointManifest.js";\nimport { diagnoseRuntimeWorkflow } from "./workflowDiagnosis.js";\nimport { consumerRuntimeWorkflows } from "./workflowRegistry.js";\nimport {\n  runtimeWorkflowTrace,\n  type RuntimeWorkflowTraceRecordV2,\n} from "./runtimeWorkflowTrace.js";\n\nconst SCAN_STATUSES = ["running", "interrupted", "completed", "failed", "stopped"] as const;\nconst SCAN_TYPES = ["quick", "full", "spam"] as const;\nconst COUNTER_KEYS = ["examined", "safe", "review", "highRisk", "confirmedThreat", "unknown", "skipped", "malformed"] as const;\n\nexport function scanHistoryDiagnostics(records: ScanHistoryRecord[]) {\n  const statusCounts = Object.fromEntries(SCAN_STATUSES.map((status) => [status, 0])) as Record<typeof SCAN_STATUSES[number], number>;\n  const typeCounts = Object.fromEntries(SCAN_TYPES.map((type) => [type, 0])) as Record<typeof SCAN_TYPES[number], number>;\n  const counters = Object.fromEntries(COUNTER_KEYS.map((key) => [key, 0])) as Record<typeof COUNTER_KEYS[number], number>;\n  let latestStartedAt: number | null = null;\n  let latestCompletedAt: number | null = null;\n  for (const record of records) {\n    statusCounts[record.status] += 1;\n    typeCounts[record.type] += 1;\n    for (const key of COUNTER_KEYS) counters[key] += Math.max(0, Math.floor(record.counters[key]));\n    latestStartedAt = latestStartedAt === null ? record.startedAt : Math.max(latestStartedAt, record.startedAt);\n    if (record.completedAt !== null) {\n      latestCompletedAt = latestCompletedAt === null ? record.completedAt : Math.max(latestCompletedAt, record.completedAt);\n    }\n  }\n  return {\n    scope: "persisted_local_scan_history" as const,\n    retainedRecords: records.length,\n    statusCounts,\n    typeCounts,\n    counters,\n    latestStartedAt,\n    latestCompletedAt,\n  };\n}\n\nexport function cleanupWorkflowDiagnostics(activity: PublicConsumerActivityRecord[]) {\n  let movedToTrash = 0;\n  let noChange = 0;\n  let other = 0;\n  let latestAt: number | null = null;\n  for (const item of activity) {\n    if (item.kind !== "cleanup") continue;\n    latestAt = latestAt === null ? item.createdAt : Math.max(latestAt, item.createdAt);\n    if (item.reasonCodes.includes("BULK_CLEANUP_TO_TRASH")) movedToTrash += 1;\n    else if (item.reasonCodes.includes("BULK_CLEANUP_NO_CHANGE")) noChange += 1;\n    else other += 1;\n  }\n  return {\n    scope: "persisted_local_activity" as const,\n    completedWithMutation: movedToTrash,\n    completedWithoutMutation: noChange,\n    otherCleanupRecords: other,\n    latestAt,\n  };\n}\n\nexport function runtimeWorkflowDiagnosisSummaries(\n  manifest: RuntimeTraceCheckpointManifest | null = null,\n) {\n  const recorder = runtimeWorkflowTrace();\n  if (!recorder?.enabled) {\n    return {\n      available: false,\n      scope: "current_diagnostic_run" as const,\n      buildId: recorder?.buildId ?? null,\n      ownerAttributionAvailable: false,\n      summaries: [],\n    };\n  }\n\n  const definitions = new Map(consumerRuntimeWorkflows().map((definition) => [definition.workflowId, definition]));\n  const records = recorder.readCurrent(2_000).filter((record): record is RuntimeWorkflowTraceRecordV2 => record.schemaVersion === 2);\n  const groups = new Map<string, { traceId: string; workflowId: string; buildId: string; records: RuntimeWorkflowTraceRecordV2[] }>();\n  for (const record of records) {\n    if (!definitions.has(record.workflowId)) continue;\n    const key = record.traceId + ":" + record.workflowId;\n    const group = groups.get(key) ?? {\n      traceId: record.traceId,\n      workflowId: record.workflowId,\n      buildId: record.buildId,\n      records: [],\n    };\n    group.records.push(record);\n    groups.set(key, group);\n  }\n\n  const summaries = [...groups.values()].slice(-40).flatMap((group) => {\n    const workflow = definitions.get(group.workflowId);\n    if (!workflow) return [];\n    const matchingManifest = manifest && manifest.buildId === group.buildId\n      ? manifest\n      : { schemaVersion: 1 as const, buildId: group.buildId, checkpoints: [] };\n    const diagnosis = diagnoseRuntimeWorkflow({\n      traceId: group.traceId,\n      records: group.records,\n      workflow,\n      manifest: matchingManifest,\n    });\n    return [{\n      workflowId: diagnosis.workflowId,\n      terminalOutcome: diagnosis.terminalOutcome,\n      lastSuccessfulCheckpoint: diagnosis.lastSuccessfulCheckpoint,\n      firstMissingCheckpoint: diagnosis.firstMissingCheckpoint,\n      failedCheckpoint: diagnosis.failedCheckpoint,\n      suspectedOwner: diagnosis.suspectedOwner\n        ? {\n            component: diagnosis.suspectedOwner.component,\n            sourcePath: diagnosis.suspectedOwner.sourcePath,\n            owner: diagnosis.suspectedOwner.owner,\n            line: diagnosis.suspectedOwner.line,\n            buildId: diagnosis.suspectedOwner.buildId,\n          }\n        : null,\n    }];\n  });\n\n  return {\n    available: true,\n    scope: "current_diagnostic_run" as const,\n    buildId: recorder.buildId,\n    ownerAttributionAvailable: Boolean(manifest && manifest.buildId === recorder.buildId),\n    summaries,\n  };\n}\n`);

const routesPath = "server/src/api/consumerProtectionRoutes.ts";
replaceOnce(
  routesPath,
  `import { defaultConsumerStateRepository } from "./defaultConsumerStateRepository.js";`,
  `import { defaultConsumerStateRepository } from "./defaultConsumerStateRepository.js";\nimport { defaultScanStateRepository } from "./defaultScanStateRepository.js";`,
);
replaceOnce(
  routesPath,
  `import type { Provider } from "../canonical/envelope.js";`,
  `import type { Provider } from "../canonical/envelope.js";\nimport type { BackgroundProtectionCoordinator } from "./backgroundProtection.js";\nimport {\n  cleanupWorkflowDiagnostics,\n  runtimeWorkflowDiagnosisSummaries,\n  scanHistoryDiagnostics,\n} from "../diagnostics/supportBundleDiagnostics.js";`,
);
replaceOnce(
  routesPath,
  `  exposureLookup?: ExposureLookupPort;\n}`,
  `  exposureLookup?: ExposureLookupPort;\n  backgroundProtection?: Pick<BackgroundProtectionCoordinator, "status" | "diagnosticSnapshot">;\n}`,
);
replaceOnce(
  routesPath,
  `    worker.on("message", (message: any) => {\n      if (message?.type === "result") finish(null, message.result);`,
  `    worker.on("message", (message: any) => {\n      if (message?.operationalMetrics) {\n        localOperationalMetrics.mergeWorkerAdapterSnapshot(message.operationalMetrics);\n      }\n      if (message?.type === "result") finish(null, message.result);`,
);
replaceOnce(
  routesPath,
  `  const exposureLookup = dependencies.exposureLookup ?? exposurePortFromEnvironment();`,
  `  const exposureLookup = dependencies.exposureLookup ?? exposurePortFromEnvironment();\n  const backgroundProtection = dependencies.backgroundProtection;`,
);

const supportMarker = `  app.get("/api/consumer/v1/support-bundle", (_req, res) => {`;
const supportTail = `  app.get("/api/consumer/v1/support-bundle", (_req, res) => {\n    try {\n      const sessionList = sessions.list();\n      const connected = sessionList.map((session) => ({\n        provider: session.config.provider,\n        mode: session.config.mode,\n        credentialStorage: session.config.mode === "live" ? "native_vault_reference" : "fixture",\n      }));\n      const activityRecords = sessionList.flatMap((session) => defaultConsumerStateRepository.listActivity(session.policyAccountKey));\n      const activityCounts = activityRecords.reduce<Record<string, number>>((counts, item) => {\n        counts[item.kind] = (counts[item.kind] ?? 0) + 1;\n        return counts;\n      }, {});\n      const scanRecords = sessionList.flatMap((session) => defaultScanStateRepository.list(session.policyAccountKey));\n      const operational = localOperationalMetrics.snapshot();\n      const backgroundStatuses = backgroundProtection\n        ? sessionList.map((session) => {\n            try {\n              const status = backgroundProtection.status(session.policyAccountKey);\n              return {\n                provider: session.config.provider,\n                enabled: status.enabled,\n                active: status.active,\n                status: status.status,\n                nextRunAt: status.nextRunAt,\n                lastAttemptAt: status.lastAttemptAt,\n                lastCompletedAt: status.lastCompletedAt,\n                consecutiveFailures: status.consecutiveFailures,\n                lastErrorCode: status.lastErrorCode,\n              };\n            } catch {\n              return { provider: session.config.provider, status: "unavailable" as const };\n            }\n          })\n        : [];\n      const releaseIdentity = resolveRuntimeReleaseIdentity();\n      noStore(res);\n      res.json({\n        schemaVersion: 1,\n        generatedAt: new Date().toISOString(),\n        app: { version: releaseIdentity.version, release: releaseIdentity.release },\n        runtime: { node: process.version, platform: process.platform, arch: process.arch },\n        connected,\n        activityCounts,\n        activityScope: {\n          scope: "persisted_local_activity",\n          persistent: defaultConsumerStateRepository.persistent,\n          connectedAccountCount: sessionList.length,\n        },\n        operationalScope: {\n          scope: operational.scope,\n          resetsOnProcessRestart: true,\n          workerAdapterAggregatesMergedIntoMainProcess: true,\n        },\n        scanHistory: scanHistoryDiagnostics(scanRecords),\n        cleanup: cleanupWorkflowDiagnostics(activityRecords),\n        backgroundProtection: {\n          available: Boolean(backgroundProtection),\n          coordinator: backgroundProtection?.diagnosticSnapshot() ?? null,\n          statuses: backgroundStatuses,\n        },\n        workflowDiagnosis: runtimeWorkflowDiagnosisSummaries(),\n        operational,\n        privacy: "no_credentials_tokens_mail_content_subject_sender_url_family_private_data_or_device_keys",\n      });\n    } catch (error) { errorResponse(res, error, 500); }\n  });\n}\n`;
replaceTail(
  routesPath,
  supportMarker,
  `privacy: "no_credentials_tokens_mail_content_subject_sender_url_family_private_data_or_device_keys"`,
  supportTail,
);

const consumerDesktopPath = "server/src/api/consumerDesktopServer.ts";
replaceOnce(
  consumerDesktopPath,
  `import { registerConsumerProtectionRoutes } from "./consumerProtectionRoutes.js";`,
  `import { registerConsumerProtectionRoutes } from "./consumerProtectionRoutes.js";\nimport { createBackgroundProtectionCoordinator } from "./backgroundProtection.js";`,
);
replaceOnce(
  consumerDesktopPath,
  `  const security = localOptions.security ?? localSecurity;\n  const community = localOptions.community ?? communityNetwork;\n  const app = express();`,
  `  const security = localOptions.security ?? localSecurity;\n  const community = localOptions.community ?? communityNetwork;\n  const backgroundProtection = localOptions.backgroundProtection\n    ?? createBackgroundProtectionCoordinator(community, localOptions.accountPlatform);\n  const app = express();`,
);
replaceOnce(
  consumerDesktopPath,
  `    destinationAnalyzer: localOptions.destinationAnalyzer,\n    exposureLookup,\n  });`,
  `    destinationAnalyzer: localOptions.destinationAnalyzer,\n    exposureLookup,\n    backgroundProtection,\n  });`,
);
replaceOnce(
  consumerDesktopPath,
  `    ...localOptions,\n    security,\n    community,\n  }));`,
  `    ...localOptions,\n    security,\n    community,\n    backgroundProtection,\n  }));`,
);

console.log("EMA-20 guarded production transform applied.");
