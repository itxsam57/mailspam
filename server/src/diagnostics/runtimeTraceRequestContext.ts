import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
import type { Provider } from "../canonical/envelope.js";
import { runtimeWorkflowDefinition } from "./workflowRegistry.js";
import {
  recordRuntimeTraceCheckpoint,
  type RuntimeCheckpointInput,
} from "./runtimeTraceCheckpoint.js";
import type { RuntimeWorkflowTraceRecorder } from "./runtimeWorkflowTrace.js";

export interface RuntimeTraceRequestContext {
  traceId: string;
  workflowId: string;
  actionId: string;
  provider?: Provider;
  scanType?: "quick" | "full" | "spam";
}

export interface ResolvedRuntimeTraceWorkflow {
  workflowId: string;
  actionId: string;
  provider?: Provider;
  scanType?: "quick" | "full" | "spam";
}

export type RuntimeTraceCheckpointFields = Omit<
  RuntimeCheckpointInput,
  "traceId" | "workflowId" | "actionId" | "checkpointId" | "provider" | "scanType"
>;

type HeaderValue = string | string[] | undefined;
type RuntimeTraceHeaders = Record<string, HeaderValue>;

const storage = new AsyncLocalStorage<RuntimeTraceRequestContext | null>();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SAFE_LABEL = /^[a-z0-9][a-z0-9_.:/-]{0,159}$/i;
const PROVIDERS = new Set<Provider>(["gmail", "icloud", "outlook", "yahoo", "imap"]);
const SCAN_TYPES = new Set(["quick", "full", "spam"] as const);

function oneHeader(headers: RuntimeTraceHeaders, name: string): string | undefined {
  const value = headers[name] ?? headers[name.toLowerCase()];
  if (Array.isArray(value)) return value.length === 1 ? value[0] : undefined;
  return typeof value === "string" ? value : undefined;
}

function validResolvedWorkflow(value: ResolvedRuntimeTraceWorkflow): boolean {
  if (!SAFE_LABEL.test(value.workflowId) || !SAFE_LABEL.test(value.actionId)) return false;
  const definition = runtimeWorkflowDefinition(value.workflowId);
  if (!definition || !definition.actionIds.includes(value.actionId)) return false;
  if (value.provider !== undefined && !PROVIDERS.has(value.provider)) return false;
  if (value.scanType !== undefined && !SCAN_TYPES.has(value.scanType)) return false;
  return true;
}

/**
 * Run one request under a correlation context. The browser contributes only an
 * opaque UUID; workflow/action identity is resolved by trusted server routing
 * and checked against the canonical workflow registry. Unknown or malformed
 * trace input is treated as tracing-disabled for that request.
 */
export function runWithRuntimeTraceRequest<T>(
  headers: RuntimeTraceHeaders,
  resolved: ResolvedRuntimeTraceWorkflow,
  callback: () => T,
): T {
  const traceId = oneHeader(headers, "x-email-shield-trace-id");
  if (!traceId || !UUID.test(traceId) || !validResolvedWorkflow(resolved)) {
    return storage.run(null, callback);
  }
  const context: RuntimeTraceRequestContext = {
    traceId,
    workflowId: resolved.workflowId,
    actionId: resolved.actionId,
    ...(resolved.provider ? { provider: resolved.provider } : {}),
    ...(resolved.scanType ? { scanType: resolved.scanType } : {}),
  };
  return storage.run(context, callback);
}

export function currentRuntimeTraceContext(): RuntimeTraceRequestContext | null {
  return storage.getStore() ?? null;
}

export function recordCurrentRuntimeCheckpoint(
  recorder: RuntimeWorkflowTraceRecorder | null,
  checkpointSuffix: string,
  fields: RuntimeTraceCheckpointFields,
): boolean {
  const context = currentRuntimeTraceContext();
  if (!context || !SAFE_LABEL.test(checkpointSuffix) || checkpointSuffix.includes("..")) return false;
  const checkpointId = `${context.workflowId}.${checkpointSuffix}`;
  if (!SAFE_LABEL.test(checkpointId)) return false;
  return recordRuntimeTraceCheckpoint(recorder, {
    traceId: context.traceId,
    workflowId: context.workflowId,
    actionId: context.actionId,
    checkpointId,
    ...(context.provider ? { provider: context.provider } : {}),
    ...(context.scanType ? { scanType: context.scanType } : {}),
    ...fields,
  });
}

/** Background work gets an independent opaque root and never inherits a request. */
export function runWithAutomaticRuntimeTrace<T>(
  workflowId: string,
  callback: (context: RuntimeTraceRequestContext) => T,
  options: { provider?: Provider; scanType?: "quick" | "full" | "spam" } = {},
): T {
  const actionId = `system.${workflowId}`;
  if (!validResolvedWorkflow({ workflowId, actionId, ...options })) {
    throw new Error("Invalid automatic runtime trace workflow.");
  }
  const context: RuntimeTraceRequestContext = {
    traceId: randomUUID(),
    workflowId,
    actionId,
    ...(options.provider ? { provider: options.provider } : {}),
    ...(options.scanType ? { scanType: options.scanType } : {}),
  };
  return storage.run(context, () => callback(context));
}
