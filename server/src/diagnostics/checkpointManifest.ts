export interface RuntimeTraceCheckpointOwner {
  checkpointId: string;
  workflowId: string;
  component: string;
  sourcePath: string;
  owner: string;
  line: number;
}

export interface RuntimeTraceCheckpointManifest {
  schemaVersion: 1;
  buildId: string;
  checkpoints: RuntimeTraceCheckpointOwner[];
}

const SAFE_LABEL = /^[a-z0-9][a-z0-9_.:/-]{0,159}$/i;
const COMMIT_SHA = /^[0-9a-f]{40}$/i;
const OWNER = /^[A-Za-z_$][A-Za-z0-9_$.:/-]{0,159}$/;
const SOURCE_PATH = /^(?:server\/src|web)\/[A-Za-z0-9_./-]{1,240}$/;
const ENTRY_KEYS = new Set(["checkpointId", "workflowId", "component", "sourcePath", "owner", "line"]);
const MANIFEST_KEYS = new Set(["schemaVersion", "buildId", "checkpoints"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validSourcePath(value: unknown): value is string {
  if (typeof value !== "string" || !SOURCE_PATH.test(value)) return false;
  if (value.startsWith("/") || value.includes("\\") || value.split("/").includes("..")) return false;
  return true;
}

function parseEntry(value: unknown): RuntimeTraceCheckpointOwner | null {
  if (!isRecord(value) || Object.keys(value).some((key) => !ENTRY_KEYS.has(key))) return null;
  if (typeof value.checkpointId !== "string" || !SAFE_LABEL.test(value.checkpointId) || value.checkpointId.includes("${")) return null;
  if (typeof value.workflowId !== "string" || !SAFE_LABEL.test(value.workflowId) || value.workflowId.includes("${")) return null;
  if (typeof value.component !== "string" || !SAFE_LABEL.test(value.component)) return null;
  if (!validSourcePath(value.sourcePath)) return null;
  if (typeof value.owner !== "string" || !OWNER.test(value.owner)) return null;
  if (!Number.isSafeInteger(value.line) || Number(value.line) < 1 || Number(value.line) > 5_000_000) return null;
  return {
    checkpointId: value.checkpointId,
    workflowId: value.workflowId,
    component: value.component,
    sourcePath: value.sourcePath,
    owner: value.owner,
    line: Number(value.line),
  };
}

export function validateCheckpointManifest(
  value: unknown,
  options: { buildId: string },
): RuntimeTraceCheckpointManifest | null {
  if (!isRecord(value) || Object.keys(value).some((key) => !MANIFEST_KEYS.has(key))) return null;
  if (value.schemaVersion !== 1) return null;
  if (typeof value.buildId !== "string" || !COMMIT_SHA.test(value.buildId)) return null;
  if (!COMMIT_SHA.test(options.buildId) || value.buildId.toLowerCase() !== options.buildId.toLowerCase()) return null;
  if (!Array.isArray(value.checkpoints) || value.checkpoints.length > 20_000) return null;

  const checkpoints: RuntimeTraceCheckpointOwner[] = [];
  const ids = new Set<string>();
  for (const candidate of value.checkpoints) {
    const entry = parseEntry(candidate);
    if (!entry || ids.has(entry.checkpointId)) return null;
    ids.add(entry.checkpointId);
    checkpoints.push(entry);
  }

  return {
    schemaVersion: 1,
    buildId: value.buildId.toLowerCase(),
    checkpoints,
  };
}

export function checkpointOwner(
  manifest: RuntimeTraceCheckpointManifest,
  checkpointId: string,
): RuntimeTraceCheckpointOwner | null {
  return manifest.checkpoints.find((entry) => entry.checkpointId === checkpointId) ?? null;
}
