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
  | "provider";

export type RuntimeWorkflowTraceOutcome =
  | "started"
  | "success"
  | "failed"
  | "partial"
  | "cancelled"
  | "rejected";

export interface RuntimeWorkflowTraceEvent {
  traceId: string;
  stage: RuntimeWorkflowTraceStage;
  actionId: string;
  expectedWorkflow: string;
  provider?: Provider;
  scanType?: "quick" | "full" | "spam";
  component?: string;
  step?: string;
  outcome: RuntimeWorkflowTraceOutcome;
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

export type RuntimeWorkflowTraceRecord = RuntimeWorkflowTraceEvent & {
  schemaVersion: 1;
  timestamp: string;
  runId: string;
};

export interface RuntimeWorkflowTraceRecorder {
  readonly enabled: boolean;
  readonly runId: string;
  readonly filePath: string;
  record(event: RuntimeWorkflowTraceEvent | Record<string, unknown>): boolean;
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

const EVENT_KEYS = new Set([
  "traceId",
  "stage",
  "actionId",
  "expectedWorkflow",
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
]);
const STAGES = new Set<RuntimeWorkflowTraceStage>([
  "app",
  "ui_action",
  "api_request",
  "api_response",
  "workflow",
  "worker",
  "provider",
]);
const OUTCOMES = new Set<RuntimeWorkflowTraceOutcome>([
  "started",
  "success",
  "failed",
  "partial",
  "cancelled",
  "rejected",
]);
const PROVIDERS = new Set<Provider>(["gmail", "icloud", "outlook", "yahoo", "imap"]);
const SCAN_TYPES = new Set(["quick", "full", "spam"] as const);
const HTTP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] as const);
const SAFE_LABEL = /^[a-z0-9][a-z0-9_.:/-]{0,159}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAX_FILES = 3;
const MAX_READ_RECORDS = 2_000;

function safePositiveInteger(value: unknown, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return Number.isSafeInteger(value) && Number(value) >= 0 && Number(value) <= maximum;
}

function validOptionalLabel(value: unknown): value is string | undefined {
  return value === undefined || (typeof value === "string" && SAFE_LABEL.test(value));
}

function isTraceEvent(value: unknown): value is RuntimeWorkflowTraceEvent {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => !EVENT_KEYS.has(key))) return false;
  if (typeof record.traceId !== "string" || !UUID.test(record.traceId)) return false;
  if (typeof record.stage !== "string" || !STAGES.has(record.stage as RuntimeWorkflowTraceStage)) return false;
  if (typeof record.actionId !== "string" || !SAFE_LABEL.test(record.actionId)) return false;
  if (typeof record.expectedWorkflow !== "string" || !SAFE_LABEL.test(record.expectedWorkflow)) return false;
  if (typeof record.outcome !== "string" || !OUTCOMES.has(record.outcome as RuntimeWorkflowTraceOutcome)) return false;
  if (record.provider !== undefined && (typeof record.provider !== "string" || !PROVIDERS.has(record.provider as Provider))) return false;
  if (record.scanType !== undefined && (typeof record.scanType !== "string" || !SCAN_TYPES.has(record.scanType as "quick" | "full" | "spam"))) return false;
  if (!validOptionalLabel(record.component) || !validOptionalLabel(record.step) || !validOptionalLabel(record.errorCode)) return false;
  if (!validOptionalLabel(record.routeTemplate)) return false;
  if (record.httpMethod !== undefined && (typeof record.httpMethod !== "string" || !HTTP_METHODS.has(record.httpMethod as RuntimeWorkflowTraceEvent["httpMethod"]))) return false;
  if (record.httpStatus !== undefined && !safePositiveInteger(record.httpStatus, 599)) return false;
  if (record.durationMs !== undefined && !safePositiveInteger(record.durationMs, 24 * 60 * 60 * 1_000)) return false;
  if (record.pageSize !== undefined && !safePositiveInteger(record.pageSize, 10_000)) return false;
  if (record.maxMessages !== undefined && !safePositiveInteger(record.maxMessages, 10_000_000)) return false;
  if (record.itemCount !== undefined && !safePositiveInteger(record.itemCount, 10_000_000)) return false;
  if (record.retryCount !== undefined && !safePositiveInteger(record.retryCount, 1_000)) return false;
  return true;
}

function sanitizedRecord(
  event: RuntimeWorkflowTraceEvent,
  runId: string,
  now: () => number,
): RuntimeWorkflowTraceRecord {
  return {
    schemaVersion: 1,
    timestamp: new Date(now()).toISOString(),
    runId,
    ...event,
  };
}

export function createRuntimeWorkflowTraceRecorder(
  options: RuntimeWorkflowTraceRecorderOptions,
): RuntimeWorkflowTraceRecorder {
  const environment = options.environment ?? process.env;
  const enabled = environment.EMAIL_SHIELD_RUNTIME_TRACE === "1";
  const runId = options.runId && UUID.test(options.runId) ? options.runId : randomUUID();
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

  function record(event: RuntimeWorkflowTraceEvent | Record<string, unknown>): boolean {
    if (!enabled || !isTraceEvent(event)) return false;
    try {
      mkdirSync(directory, { recursive: true, mode: 0o700 });
      const line = `${JSON.stringify(sanitizedRecord(event, runId, now))}\n`;
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
            const parsed = JSON.parse(line) as RuntimeWorkflowTraceRecord;
            return parsed.schemaVersion === 1 && parsed.runId === runId ? [parsed] : [];
          } catch {
            return [];
          }
        });
    } catch {
      return [];
    }
  }

  return { enabled, runId, filePath, record, readCurrent, traceFiles };
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
