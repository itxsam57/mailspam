import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
import type { Provider } from "../canonical/envelope.js";
import { runtimeWorkflowTrace } from "./runtimeWorkflowTrace.js";

export interface RuntimeTraceRequestContext {
  traceId: string;
  workflowId: string;
  actionId: string;
  expectedWorkflow: string;
  provider?: Provider;
  scanType?: "quick" | "full" | "spam";
}

export interface RuntimeTraceCheckpointFields {
  stage: "app" | "ui_action" | "api_request" | "api_response" | "workflow" | "worker" | "provider" | "service" | "storage" | "vault" | "community" | "family" | "ui_render" | "system";
  outcome: "started" | "success" | "failed" | "partial" | "cancelled" | "rejected" | "incomplete";
  component?: string;
  step?: string;
  errorCode?: string;
  httpStatus?: number;
  durationMs?: number;
  pageSize?: number;
  maxMessages?: number;
  itemCount?: number;
  retryCount?: number;
}

type HeaderValue = string | string[] | undefined;
type RuntimeTraceHeaders = Record<string, HeaderValue>;

const storage = new AsyncLocalStorage<RuntimeTraceRequestContext | null>();
const SAFE_LABEL = /^[a-z0-9][a-z0-9_.:/-]{0,159}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PROVIDERS = new Set<Provider>(["gmail", "icloud", "outlook", "yahoo", "imap"]);
const SCAN_TYPES = new Set(["quick", "full", "spam"] as const);

function oneHeader(headers: RuntimeTraceHeaders, name: string): string | undefined {
  const direct = headers[name];
  const fallback = headers[name.toLowerCase()];
  const value = direct ?? fallback;
  if (Array.isArray(value)) return value.length === 1 ? value[0] : undefined;
  return typeof value === "string" ? value : undefined;
}

function safeLabel(value: unknown): value is string {
  return typeof value === "string" && SAFE_LABEL.test(value);
}

function safeProvider(value: unknown): Provider | undefined {
  return typeof value === "string" && PROVIDERS.has(value as Provider) ? value as Provider : undefined;
}

function safeScanType(value: unknown): "quick" | "full" | "spam" | undefined {
  return typeof value === "string" && SCAN_TYPES.has(value as "quick" | "full" | "spam")
    ? value as "quick" | "full" | "spam"
    : undefined;
}

function clearContext(): void {
  storage.enterWith(null);
}

export function bindRuntimeTraceRequest(headers: RuntimeTraceHeaders): boolean {
  const traceId = oneHeader(headers, "x-email-shield-trace-id");
  const workflowId = oneHeader(headers, "x-email-shield-workflow-id");
  const actionId = oneHeader(headers, "x-email-shield-action-id");
  const providerHeader = oneHeader(headers, "x-email-shield-provider");
  const scanTypeHeader = oneHeader(headers, "x-email-shield-scan-type");

  if (!traceId && !workflowId && !actionId && !providerHeader && !scanTypeHeader) {
    clearContext();
    return false;
  }
  if (!traceId || !UUID.test(traceId) || !safeLabel(workflowId) || !safeLabel(actionId)) {
    clearContext();
    return false;
  }
  const provider = safeProvider(providerHeader);
  if (providerHeader !== undefined && !provider) {
    clearContext();
    return false;
  }
  const scanType = safeScanType(scanTypeHeader);
  if (scanTypeHeader !== undefined && !scanType) {
    clearContext();
    return false;
  }

  storage.enterWith({
    traceId,
    workflowId,
    actionId,
    expectedWorkflow: workflowId,
    ...(provider ? { provider } : {}),
    ...(scanType ? { scanType } : {}),
  });
  return true;
}

export function currentRuntimeTraceContext(): RuntimeTraceRequestContext | null {
  return storage.getStore() ?? null;
}

export function startAutomaticRuntimeTrace(
  workflowId: string,
  component: string,
  provider?: Provider,
): RuntimeTraceRequestContext {
  if (!safeLabel(workflowId) || !safeLabel(component) || (provider !== undefined && !PROVIDERS.has(provider))) {
    throw new Error("Invalid automatic runtime trace definition.");
  }
  const context: RuntimeTraceRequestContext = {
    traceId: randomUUID(),
    workflowId,
    actionId: `system.${workflowId}`,
    expectedWorkflow: workflowId,
    ...(provider ? { provider } : {}),
  };
  storage.enterWith(context);
  return context;
}

export function recordCurrentRuntimeCheckpoint(
  checkpointSuffix: string,
  fields: RuntimeTraceCheckpointFields,
): boolean {
  const context = currentRuntimeTraceContext();
  if (!context || !safeLabel(checkpointSuffix) || checkpointSuffix.includes("..")) return false;
  const checkpointId = `${context.workflowId}.${checkpointSuffix}`;
  if (!safeLabel(checkpointId)) return false;
  return runtimeWorkflowTrace()?.record({
    traceId: context.traceId,
    workflowId: context.workflowId,
    actionId: context.actionId,
    expectedWorkflow: context.expectedWorkflow,
    checkpointId,
    stage: fields.stage,
    outcome: fields.outcome,
    ...(context.provider ? { provider: context.provider } : {}),
    ...(context.scanType ? { scanType: context.scanType } : {}),
    ...(fields.component ? { component: fields.component } : {}),
    ...(fields.step ? { step: fields.step } : {}),
    ...(fields.errorCode ? { errorCode: fields.errorCode } : {}),
    ...(fields.httpStatus !== undefined ? { httpStatus: fields.httpStatus } : {}),
    ...(fields.durationMs !== undefined ? { durationMs: fields.durationMs } : {}),
    ...(fields.pageSize !== undefined ? { pageSize: fields.pageSize } : {}),
    ...(fields.maxMessages !== undefined ? { maxMessages: fields.maxMessages } : {}),
    ...(fields.itemCount !== undefined ? { itemCount: fields.itemCount } : {}),
    ...(fields.retryCount !== undefined ? { retryCount: fields.retryCount } : {}),
  }) ?? false;
}
