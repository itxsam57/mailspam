import { randomUUID } from "node:crypto";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
} from "node:fs";
import { join } from "node:path";
import type { Provider } from "../canonical/envelope.js";

export type RuntimeWorkflowTraceStage =
  | "app"
  | "ui_action"
  | "api_request"
  | "api_response"
  | "workflow"
  | "worker"
  | "provider"
  | "service"
  | "storage"
  | "vault"
  | "community"
  | "family"
  | "ui_render"
  | "system";

export type RuntimeWorkflowTraceOutcome =
  | "started"
  | "success"
  | "failed"
  | "partial"
  | "cancelled"
  | "rejected"
  | "incomplete";

interface RuntimeWorkflowTraceSafeMetadata {
  provider?: Provider;
  scanType?: "quick" | "full" | "spam";
  component?: string;
  step?: string;
  routeTemplate?: string;
  httpMethod?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";
  httpStatus?: number;
  durationMs?: number;
  pageSize?: number;
  maxMessages?: number;
  itemCount?: number;
  retryCount?: number;
  errorCode?: string;
}

/**
 * Schema-v1 input retained during the staged recorder migration. Existing
 * producers remain valid until they are moved to the workflow/checkpoint
 * contract. New product instrumentation must use RuntimeWorkflowTraceEventV2.
 */
export interface RuntimeWorkflowTraceEvent extends RuntimeWorkflowTraceSafeMetadata {
  traceId: string;
  stage: RuntimeWorkflowTraceStage;
  actionId: string;
  expectedWorkflow: string;
  outcome: RuntimeWorkflowTraceOutcome;
}

export interface RuntimeWorkflowTraceEventV2 extends RuntimeWorkflowTraceSafeMetadata {
  traceId: string;
  workflowId: string;
  actionId: string;
  stage: RuntimeWorkflowTraceStage;
  outcome: RuntimeWorkflowTraceOutcome;
  checkpointId?: string;
  expectedWorkflow?: string;
  parentTraceId?: string;
  errorLocationId?: string;
}

export type RuntimeWorkflowTraceRecordV1 = RuntimeWorkflowTraceEvent & {
  schemaVersion: 1;
  timestamp: string;
  runId: string;
};

export type RuntimeWorkflowTraceRecordV2 = RuntimeWorkflowTraceEventV2 & {
  schemaVersion: 2;
  timestamp: string;
  runId: string;
  buildId: string;
};

export type RuntimeWorkflowTraceRecord = RuntimeWorkflowTraceRecordV1 | RuntimeWorkflowTraceRecordV2;
export type RuntimeWorkflowTraceInput = RuntimeWorkflowTraceEvent | RuntimeWorkflowTraceEventV2;

export interface RuntimeWorkflowTraceRecorder {
  readonly enabled: boolean;
  readonly runId: string;
  readonly buildId: string;
  readonly filePath: string;
  record(event: RuntimeWorkflowTraceInput | Record<string, unknown>): boolean;
  readCurrent(limit?: number): RuntimeWorkflowTraceRecord[];
  traceFiles(): string[];
}

interface RuntimeWorkflowTraceRecorderOptions {
  dataDirectory: string;
  environment?: Record<string, string | undefined>;
  runId?: string;
  now?: () => number;
  maxBytes?: number;
  maxFiles?: number;
}

const COMMON_EVENT_KEYS = [
  "traceId",
  "stage",
  "actionId",
  "provider",
  "scanType",
  "component",
  "step",
  "outcome",
  "routeTemplate",
  "httpMethod",
  "httpStatus",
  "durationMs",
  "pageSize",
  "maxMessages",
  "itemCount",
  "retryCount",
  "errorCode",
] as const;
const V1_EVENT_KEYS = new Set([...COMMON_EVENT_KEYS, "expectedWorkflow"]);
const V2_EVENT_KEYS = new Set([
  ...COMMON_EVENT_KEYS,
  "workflowId",
  "checkpointId",
  "expectedWorkflow",
  "parentTraceId",
  "errorLocationId",
]);
const STAGES = new Set<RuntimeWorkflowTraceStage>([
  "app",
  "ui_action",
  "api_request",
  "api_response",
  "workflow",
  "worker",
  "provider",
  "service",
  "storage",
  "vault",
  "community",
  "family",
  "ui_render",
  "system",
]);
const OUTCOMES = new Set<RuntimeWorkflowTraceOutcome>([
  "started",
  "success",
  "failed",
  "partial",
  "cancelled",
  "rejected",
  "incomplete",
]);
const PROVIDERS = new Set<Provider>(["gmail", "icloud", "outlook", "yahoo", "imap"]);
const SCAN_TYPES = new Set(["quick", "full", "spam"] as const);
const HTTP_METHODS = new Set<string>(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
const SAFE_LABEL = /^[a-z0-9][a-z0-9_.:/-]{0,159}$/i;
const SAFE_ROUTE_TEMPLATES = new Set<string>([
  "/api/accounts",
  "/api/accounts/connect",
  "/api/accounts/workspace",
  "/api/security/mutation-token",
  "/api/accounts/oauth/google/status/:flowId",
  "/api/accounts/oauth/microsoft/status/:flowId",
  "/api/accounts/:accountId/scan/:type",
  "/api/accounts/:accountId/scan/resume/:scanId",
  "/api/accounts/:accountId/scan/stop",
  "/api/accounts/:accountId/background-protection",
  "/api/accounts/:accountId/scan-history",
  "/api/accounts/:accountId/messages/:action",
  "/api/accounts/:accountId",
  "/api/profile/:operation",
  "/api/scam-check/:operation",
  "/api/consumer/:operation",
  "/api/dev/runtime-trace/:operation",
  "/api/operations/:operation",
  "/api/other",
]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const COMMIT_SHA = /^[0-9a-f]{40}$/i;
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAX_FILES = 3;
const MAX_READ_RECORDS = 2_000;

function safePositiveInteger(value: unknown, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0 && Number(value) <= maximum;
}

function validOptionalLabel(value: unknown): value is string | undefined {
  return value === undefined || (typeof value === "string" && SAFE_LABEL.test(value));
}

function validOptionalRouteTemplate(value: unknown): value is string | undefined {
  return value === undefined || (typeof value === "string" && SAFE_ROUTE_TEMPLATES.has(value));
}

function validCommonEventFields(record: Record<string, unknown>): boolean {
  if (typeof record.traceId !== "string" || !UUID.test(record.traceId)) return false;
  if (typeof record.stage !== "string" || !STAGES.has(record.stage as RuntimeWorkflowTraceStage)) return false;
  if (typeof record.actionId !== "string" || !SAFE_LABEL.test(record.actionId)) return false;
  if (typeof record.outcome !== "string" || !OUTCOMES.has(record.outcome as RuntimeWorkflowTraceOutcome)) return false;
  if (record.provider !== undefined && (typeof record.provider !== "string" || !PROVIDERS.has(record.provider as Provider))) return false;
  if (record.scanType !== undefined && (typeof record.scanType !== "string" || !SCAN_TYPES.has(record.scanType as "quick" | "full" | "spam"))) return false;
  if (!validOptionalLabel(record.component) || !validOptionalLabel(record.step) || !validOptionalLabel(record.errorCode)) return false;
  if (!validOptionalRouteTemplate(record.routeTemplate)) return false;
  const httpMethod = record.httpMethod;
  if (httpMethod !== undefined && (typeof httpMethod !== "string" || !HTTP_METHODS.has(httpMethod))) return false;
  if (record.httpStatus !== undefined && !safePositiveInteger(record.httpStatus, 599)) return false;
  if (record.durationMs !== undefined && !safePositiveInteger(record.durationMs, 24 * 60 * 60 * 1_000)) return false;
  if (record.pageSize !== undefined && !safePositiveInteger(record.pageSize, 10_000)) return false;
  if (record.maxMessages !== undefined && !safePositiveInteger(record.maxMessages, 10_000_000)) return false;
  if (record.itemCount !== undefined && !safePositiveInteger(record.itemCount, 10_000_000)) return false;
  if (record.retryCount !== undefined && !safePositiveInteger(record.retryCount, 1_000)) return false;
  return true;
}

function isTraceEventV1(value: unknown): value is RuntimeWorkflowTraceEvent {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !V1_EVENT_KEYS.has(key))) return false;
  if (!validCommonEventFields(record)) return false;
  return typeof record.expectedWorkflow === "string" && SAFE_LABEL.test(record.expectedWorkflow);
}

function isTraceEventV2(value: unknown): value is RuntimeWorkflowTraceEventV2 {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !V2_EVENT_KEYS.has(key))) return false;
  if (!validCommonEventFields(record)) return false;
  if (typeof record.workflowId !== "string" || !SAFE_LABEL.test(record.workflowId)) return false;
  if (!validOptionalLabel(record.checkpointId)) return false;
  if (!validOptionalLabel(record.expectedWorkflow)) return false;
  if (!validOptionalLabel(record.errorLocationId)) return false;
  if (record.parentTraceId !== undefined && (typeof record.parentTraceId !== "string" || !UUID.test(record.parentTraceId))) return false;
  return true;
}

function sanitizedRecordV1(
  event: RuntimeWorkflowTraceEvent,
  runId: string,
  now: () => number,
): RuntimeWorkflowTraceRecordV1 {
  return {
    schemaVersion: 1,
    timestamp: new Date(now()).toISOString(),
    runId,
    ...event,
  };
}

function sanitizedRecordV2(
  event: RuntimeWorkflowTraceEventV2,
  runId: string,
  buildId: string,
  now: () => number,
): RuntimeWorkflowTraceRecordV2 {
  return {
    schemaVersion: 2,
    timestamp: new Date(now()).toISOString(),
    runId,
    buildId,
    ...event,
  };
}

function resolveBuildId(environment: Record<string, string | undefined>): string {
  const candidate = environment.EMAIL_SHIELD_BUILD_COMMIT?.trim()
    || environment.GITHUB_SHA?.trim()
    || "";
  return COMMIT_SHA.test(candidate) ? candidate.toLowerCase() : "development";
}

function isStoredV1Record(value: unknown, runId: string): value is RuntimeWorkflowTraceRecordV1 {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (record.schemaVersion !== 1 || record.runId !== runId) return false;
  if (typeof record.timestamp !== "string" || !ISO_TIMESTAMP.test(record.timestamp)) return false;
  const { schemaVersion: _schemaVersion, timestamp: _timestamp, runId: _runId, ...event } = record;
  return isTraceEventV1(event);
}

function isStoredV2Record(value: unknown, runId: string): value is RuntimeWorkflowTraceRecordV2 {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (record.schemaVersion !== 2 || record.runId !== runId) return false;
  if (typeof record.timestamp !== "string" || !ISO_TIMESTAMP.test(record.timestamp)) return false;
  if (typeof record.buildId !== "string" || !(record.buildId === "development" || COMMIT_SHA.test(record.buildId))) return false;
  const {
    schemaVersion: _schemaVersion,
    timestamp: _timestamp,
    runId: _runId,
    buildId: _buildId,
    ...event
  } = record;
  return isTraceEventV2(event);
}

export function createRuntimeWorkflowTraceRecorder(
  options: RuntimeWorkflowTraceRecorderOptions,
): RuntimeWorkflowTraceRecorder {
  const environment = options.environment ?? process.env;
  const enabled = environment.EMAIL_SHIELD_RUNTIME_TRACE === "1";
  const runId = options.runId && UUID.test(options.runId) ? options.runId : randomUUID();
  const buildId = resolveBuildId(environment);
  const now = options.now ?? Date.now;
  const maxBytes = Math.max(512, Math.trunc(options.maxBytes ?? DEFAULT_MAX_BYTES));
  const maxFiles = Math.max(1, Math.min(10, Math.trunc(options.maxFiles ?? DEFAULT_MAX_FILES)));
  const directory = join(options.dataDirectory, "diagnostics");
  const filePath = join(directory, "runtime-workflow-trace.jsonl");

  function rotatedPath(index: number): string {
    return `${filePath}.${index}`;
  }

  function traceFiles(): string[] {
    const files: string[] = [];
    if (existsSync(filePath)) files.push(filePath);
    for (let index = 1; index < maxFiles; index += 1) {
      const candidate = rotatedPath(index);
      if (existsSync(candidate)) files.push(candidate);
    }
    return files;
  }

  function rotateIfNeeded(bytesToAppend: number): void {
    let currentBytes = 0;
    try { currentBytes = existsSync(filePath) ? statSync(filePath).size : 0; }
    catch { currentBytes = 0; }
    if (currentBytes === 0 || currentBytes + bytesToAppend <= maxBytes) return;

    if (maxFiles <= 1) {
      rmSync(filePath, { force: true });
      return;
    }
    rmSync(rotatedPath(maxFiles - 1), { force: true });
    for (let index = maxFiles - 2; index >= 1; index -= 1) {
      const source = rotatedPath(index);
      if (existsSync(source)) renameSync(source, rotatedPath(index + 1));
    }
    if (existsSync(filePath)) renameSync(filePath, rotatedPath(1));
  }

  function record(event: RuntimeWorkflowTraceInput | Record<string, unknown>): boolean {
    if (!enabled) return false;
    const safeRecord = isTraceEventV2(event)
      ? sanitizedRecordV2(event, runId, buildId, now)
      : isTraceEventV1(event)
        ? sanitizedRecordV1(event, runId, now)
        : null;
    if (!safeRecord) return false;
    try {
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      const line = `${JSON.stringify(safeRecord)}\n`;
      const bytes = Buffer.byteLength(line, "utf8");
      if (bytes > maxBytes) return false;
      rotateIfNeeded(bytes);
      appendFileSync(filePath, line, { encoding: "utf8", mode: 0o600 });
      return true;
    } catch {
      // Diagnostics are fail-soft by design. Protection behavior must never
      // depend on the trace sink being writable or available.
      return false;
    }
  }

  function readCurrent(limit = 200): RuntimeWorkflowTraceRecord[] {
    if (!enabled || !existsSync(filePath)) return [];
    try {
      const boundedLimit = Math.max(1, Math.min(MAX_READ_RECORDS, Math.trunc(limit)));
      return readFileSync(filePath, "utf8")
        .split("\n")
        .filter(Boolean)
        .slice(-boundedLimit)
        .flatMap((line) => {
          try {
            const parsed: unknown = JSON.parse(line);
            if (isStoredV2Record(parsed, runId) || isStoredV1Record(parsed, runId)) return [parsed];
            return [];
          } catch {
            return [];
          }
        });
    } catch {
      return [];
    }
  }

  return { enabled, runId, buildId, filePath, record, readCurrent, traceFiles };
}

let defaultRecorder: RuntimeWorkflowTraceRecorder | null = null;

export function initializeRuntimeWorkflowTrace(options: RuntimeWorkflowTraceRecorderOptions): RuntimeWorkflowTraceRecorder {
  defaultRecorder = createRuntimeWorkflowTraceRecorder(options);
  return defaultRecorder;
}

export function runtimeWorkflowTrace(): RuntimeWorkflowTraceRecorder | null {
  return defaultRecorder;
}

export function isRuntimeWorkflowTraceId(value: unknown): value is string {
  return typeof value === "string" && UUID.test(value);
}
