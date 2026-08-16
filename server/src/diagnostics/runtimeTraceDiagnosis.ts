import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { runtimeWorkflowTrace, type RuntimeWorkflowTraceRecord } from "./runtimeWorkflowTrace.js";
import { runtimeWorkflowDefinition } from "./workflowRegistry.js";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SAFE_LABEL = /^[a-z0-9][a-z0-9_.:/-]{0,159}$/i;
const BUILD_ID = /^(?:development|[0-9a-f]{40})$/i;
const SOURCE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9_.\/-]{1,240}$/;

export interface RuntimeTraceManifestEntry {
  checkpointId: string;
  workflowId: string;
  component: string;
  sourcePath: string;
  owner: string;
  line: number;
  buildId: string;
}

export interface RuntimeTraceManifest {
  buildId: string;
  generatedAt?: string;
  entries: RuntimeTraceManifestEntry[];
}

export interface RuntimeTraceDiagnosis {
  traceId: string;
  workflowId: string;
  buildId: string;
  status: "success" | "failed" | "rejected" | "cancelled" | "partial" | "incomplete";
  lastCheckpointId: string | null;
  firstMissingCheckpointId: string | null;
  sourceOwner: {
    checkpointId: string;
    component: string;
    sourcePath: string;
    owner: string;
    line: number;
  } | null;
  errorCode: string | null;
}

function validManifestEntry(value: unknown, buildId: string): value is RuntimeTraceManifestEntry {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const entry = value as Record<string, unknown>;
  const keys = Object.keys(entry);
  if (keys.some((key) => !["checkpointId", "workflowId", "component", "sourcePath", "owner", "line", "buildId"].includes(key))) return false;
  return typeof entry.checkpointId === "string" && SAFE_LABEL.test(entry.checkpointId)
    && typeof entry.workflowId === "string" && SAFE_LABEL.test(entry.workflowId)
    && typeof entry.component === "string" && SAFE_LABEL.test(entry.component)
    && typeof entry.sourcePath === "string" && SOURCE_PATH.test(entry.sourcePath) && !entry.sourcePath.includes("\\")
    && typeof entry.owner === "string" && SAFE_LABEL.test(entry.owner)
    && Number.isSafeInteger(entry.line) && Number(entry.line) > 0 && Number(entry.line) <= 2_000_000
    && entry.buildId === buildId;
}

export function loadRuntimeTraceManifest(
  buildId: string,
  manifestPath = resolve(process.cwd(), "artifacts/engineering/runtime-trace-manifest.json"),
): RuntimeTraceManifest | null {
  if (!BUILD_ID.test(buildId)) return null;
  try {
    const parsed = JSON.parse(readFileSync(manifestPath, "utf8")) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    const object = parsed as Record<string, unknown>;
    if (object.buildId !== buildId || !Array.isArray(object.entries)) return null;
    const entries = object.entries;
    if (entries.some((entry) => !validManifestEntry(entry, buildId))) return null;
    const ids = new Set<string>();
    for (const entry of entries as RuntimeTraceManifestEntry[]) {
      if (ids.has(entry.checkpointId)) return null;
      ids.add(entry.checkpointId);
    }
    return {
      buildId,
      ...(typeof object.generatedAt === "string" ? { generatedAt: object.generatedAt } : {}),
      entries: entries as RuntimeTraceManifestEntry[],
    };
  } catch {
    return null;
  }
}

function successfulCheckpointIds(records: RuntimeWorkflowTraceRecord[]): Set<string> {
  return new Set(records
    .filter((record) => record.schemaVersion === 2 && record.outcome === "success" && typeof record.checkpointId === "string")
    .map((record) => record.checkpointId as string));
}

function explicitTerminal(records: RuntimeWorkflowTraceRecord[]): RuntimeWorkflowTraceRecord | null {
  for (let index = records.length - 1; index >= 0; index -= 1) {
    const record = records[index]!;
    if (record.schemaVersion !== 2) continue;
    if (["failed", "rejected", "cancelled", "partial"].includes(record.outcome)) return record;
  }
  return null;
}

function sourceFor(manifest: RuntimeTraceManifest, checkpointId: string | null) {
  if (!checkpointId) return null;
  const entry = manifest.entries.find((candidate) => candidate.checkpointId === checkpointId);
  return entry ? {
    checkpointId: entry.checkpointId,
    component: entry.component,
    sourcePath: entry.sourcePath,
    owner: entry.owner,
    line: entry.line,
  } : null;
}

export function diagnoseRuntimeTrace(
  traceId: string,
  manifestPath?: string,
): RuntimeTraceDiagnosis | null {
  if (!UUID.test(traceId)) return null;
  const recorder = runtimeWorkflowTrace();
  if (!recorder?.enabled) return null;
  const all = recorder.readCurrent(2_000)
    .filter((record) => record.schemaVersion === 2 && record.traceId === traceId);
  if (!all.length) return null;
  const latest = all.at(-1)!;
  if (latest.schemaVersion !== 2 || typeof latest.workflowId !== "string") return null;
  const workflowId = latest.workflowId;
  const buildId = latest.buildId;
  if (!BUILD_ID.test(buildId) || buildId !== recorder.buildId) return null;
  const definition = runtimeWorkflowDefinition(workflowId);
  const manifest = loadRuntimeTraceManifest(buildId, manifestPath);
  if (!definition || !manifest) return null;
  const records = all.filter((record) => record.schemaVersion === 2 && record.workflowId === workflowId && record.buildId === buildId);
  const successful = successfulCheckpointIds(records);
  const missing = definition.requiredCheckpoints.find((checkpoint) => !successful.has(checkpoint)) ?? null;
  const terminal = explicitTerminal(records);
  const lastCheckpointId = [...records].reverse().find((record) => typeof record.checkpointId === "string")?.checkpointId ?? null;

  let status: RuntimeTraceDiagnosis["status"] = "incomplete";
  let errorCode: string | null = null;
  if (terminal) {
    status = terminal.outcome as RuntimeTraceDiagnosis["status"];
    errorCode = terminal.errorCode ?? null;
  } else {
    const successTerminals = definition.terminalCheckpoints.success;
    if (!missing && successTerminals.some((checkpoint) => successful.has(checkpoint))) status = "success";
  }

  const ownerCheckpoint = terminal?.checkpointId ?? missing ?? lastCheckpointId;
  return {
    traceId,
    workflowId,
    buildId,
    status,
    lastCheckpointId,
    firstMissingCheckpointId: status === "success" ? null : missing,
    sourceOwner: sourceFor(manifest, ownerCheckpoint),
    errorCode,
  };
}
