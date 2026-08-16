type TelemetryEnvironment = Readonly<Record<string, string | undefined>>;

type TechnicalTelemetryEvent =
  | "email_shield_app_started"
  | "email_shield_protected_state_ready"
  | "email_shield_protected_state_failed"
  | "email_shield_server_listening";

type TechnicalTelemetryProperties = Readonly<{
  duration_ms?: number;
  failure_kind?: "initialization_error";
}>;

export interface TechnicalTelemetry {
  capture(event: TechnicalTelemetryEvent, properties?: TechnicalTelemetryProperties): Promise<boolean>;
  captureWorkflowTrace(record: unknown): Promise<boolean>;
}

interface TechnicalTelemetryOptions {
  environment?: TelemetryEnvironment;
  platform?: NodeJS.Platform;
  appVersion?: string;
  fetchImpl?: typeof fetch;
}

const DEFAULT_POSTHOG_HOST = "https://us.i.posthog.com";
const CAPTURE_TIMEOUT_MS = 1_500;
const ANONYMOUS_DISTINCT_ID = "email-shield-desktop-runtime";
const SAFE_LABEL = /^[a-z0-9][a-z0-9_.:/-]{0,159}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ISO_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const WORKFLOW_TRACE_KEYS = new Set([
  "schemaVersion",
  "timestamp",
  "runId",
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
const WORKFLOW_STAGES = new Set(["app", "ui_action", "api_request", "api_response", "workflow", "worker", "provider"]);
const WORKFLOW_OUTCOMES = new Set(["started", "success", "failed", "partial", "cancelled", "rejected"]);
const WORKFLOW_PROVIDERS = new Set(["gmail", "icloud", "outlook", "yahoo", "imap"]);
const WORKFLOW_SCAN_TYPES = new Set(["quick", "full", "spam"]);
const WORKFLOW_HTTP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);

const ALLOWED_EVENTS = new Set<TechnicalTelemetryEvent>([
  "email_shield_app_started",
  "email_shield_protected_state_ready",
  "email_shield_protected_state_failed",
  "email_shield_server_listening",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateProperties(
  event: TechnicalTelemetryEvent,
  properties: unknown,
): TechnicalTelemetryProperties | null {
  if (properties === undefined) {
    return event === "email_shield_protected_state_ready" || event === "email_shield_protected_state_failed"
      ? null
      : {};
  }
  if (!isRecord(properties)) return null;

  const keys = Object.keys(properties);
  if (keys.some((key) => key !== "duration_ms" && key !== "failure_kind")) return null;

  if (event === "email_shield_protected_state_ready") {
    if (keys.length !== 1 || keys[0] !== "duration_ms") return null;
    const durationMs = properties.duration_ms;
    if (typeof durationMs !== "number" || !Number.isFinite(durationMs) || durationMs < 0 || durationMs > 3_600_000) {
      return null;
    }
    return { duration_ms: Math.round(durationMs) };
  }

  if (event === "email_shield_protected_state_failed") {
    if (keys.length !== 1 || keys[0] !== "failure_kind" || properties.failure_kind !== "initialization_error") {
      return null;
    }
    return { failure_kind: "initialization_error" };
  }

  return keys.length === 0 ? {} : null;
}

function optionalLabel(value: unknown): string | undefined | null {
  if (value === undefined) return undefined;
  return typeof value === "string" && SAFE_LABEL.test(value) ? value : null;
}

function optionalInteger(value: unknown, maximum: number): number | undefined | null {
  if (value === undefined) return undefined;
  return Number.isSafeInteger(value) && Number(value) >= 0 && Number(value) <= maximum
    ? Number(value)
    : null;
}

function workflowTraceProperties(record: unknown): { timestamp: string; properties: Record<string, string | number | boolean> } | null {
  if (!isRecord(record) || Object.keys(record).some((key) => !WORKFLOW_TRACE_KEYS.has(key))) return null;
  if (record.schemaVersion !== 1) return null;
  if (typeof record.timestamp !== "string" || !ISO_TIMESTAMP.test(record.timestamp)) return null;
  if (typeof record.runId !== "string" || !UUID.test(record.runId)) return null;
  if (typeof record.traceId !== "string" || !UUID.test(record.traceId)) return null;
  if (typeof record.stage !== "string" || !WORKFLOW_STAGES.has(record.stage)) return null;
  if (typeof record.actionId !== "string" || !SAFE_LABEL.test(record.actionId)) return null;
  if (typeof record.expectedWorkflow !== "string" || !SAFE_LABEL.test(record.expectedWorkflow)) return null;
  if (typeof record.outcome !== "string" || !WORKFLOW_OUTCOMES.has(record.outcome)) return null;
  if (record.provider !== undefined && (typeof record.provider !== "string" || !WORKFLOW_PROVIDERS.has(record.provider))) return null;
  if (record.scanType !== undefined && (typeof record.scanType !== "string" || !WORKFLOW_SCAN_TYPES.has(record.scanType))) return null;
  if (record.httpMethod !== undefined && (typeof record.httpMethod !== "string" || !WORKFLOW_HTTP_METHODS.has(record.httpMethod))) return null;

  const component = optionalLabel(record.component);
  const step = optionalLabel(record.step);
  const routeTemplate = optionalLabel(record.routeTemplate);
  const errorCode = optionalLabel(record.errorCode);
  if (component === null || step === null || routeTemplate === null || errorCode === null) return null;

  const httpStatus = optionalInteger(record.httpStatus, 599);
  const durationMs = optionalInteger(record.durationMs, 86_400_000);
  const pageSize = optionalInteger(record.pageSize, 10_000);
  const maxMessages = optionalInteger(record.maxMessages, 10_000_000);
  const itemCount = optionalInteger(record.itemCount, 10_000_000);
  const retryCount = optionalInteger(record.retryCount, 1_000);
  if ([httpStatus, durationMs, pageSize, maxMessages, itemCount, retryCount].some((value) => value === null)) return null;

  return {
    timestamp: record.timestamp,
    properties: {
      run_id: record.runId,
      trace_id: record.traceId,
      stage: record.stage,
      action_id: record.actionId,
      expected_workflow: record.expectedWorkflow,
      outcome: record.outcome,
      ...(typeof record.provider === "string" ? { provider: record.provider } : {}),
      ...(typeof record.scanType === "string" ? { scan_type: record.scanType } : {}),
      ...(component ? { trace_component: component } : {}),
      ...(step ? { step } : {}),
      ...(routeTemplate ? { route_template: routeTemplate } : {}),
      ...(typeof record.httpMethod === "string" ? { http_method: record.httpMethod } : {}),
      ...(httpStatus !== undefined ? { http_status: httpStatus } : {}),
      ...(durationMs !== undefined ? { duration_ms: durationMs } : {}),
      ...(pageSize !== undefined ? { page_size: pageSize } : {}),
      ...(maxMessages !== undefined ? { max_messages: maxMessages } : {}),
      ...(itemCount !== undefined ? { item_count: itemCount } : {}),
      ...(retryCount !== undefined ? { retry_count: retryCount } : {}),
      ...(errorCode ? { error_code: errorCode } : {}),
    },
  };
}

function captureUrlFromHost(rawHost: string): URL | null {
  try {
    const host = new URL(rawHost);
    if (host.protocol !== "https:" || host.username || host.password || host.search || host.hash) return null;
    return new URL("/capture/", host);
  } catch {
    return null;
  }
}

function disabledTelemetry(): TechnicalTelemetry {
  return {
    async capture() {
      return false;
    },
    async captureWorkflowTrace() {
      return false;
    },
  };
}

export function createTechnicalTelemetryFromEnvironment(
  options: TechnicalTelemetryOptions = {},
): TechnicalTelemetry {
  const environment = options.environment ?? process.env;
  if (environment.EMAIL_SHIELD_TELEMETRY !== "1") return disabledTelemetry();

  const projectToken = environment.EMAIL_SHIELD_POSTHOG_PROJECT_TOKEN?.trim();
  if (!projectToken) return disabledTelemetry();

  const captureUrl = captureUrlFromHost(
    environment.EMAIL_SHIELD_POSTHOG_HOST?.trim() || DEFAULT_POSTHOG_HOST,
  );
  if (!captureUrl) return disabledTelemetry();

  const platform = options.platform ?? process.platform;
  const appVersion = options.appVersion?.trim() || "unknown";
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") return disabledTelemetry();

  async function send(event: string, safeProperties: Record<string, unknown>, timestamp = new Date().toISOString()): Promise<boolean> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), CAPTURE_TIMEOUT_MS);
    timeout.unref?.();

    try {
      const response = await fetchImpl(captureUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          api_key: projectToken,
          distinct_id: ANONYMOUS_DISTINCT_ID,
          event,
          timestamp,
          properties: {
            $process_person_profile: false,
            $geoip_disable: true,
            component: "desktop_server",
            app_version: appVersion,
            platform,
            ...safeProperties,
          },
        }),
        signal: controller.signal,
      });
      return response.ok;
    } catch {
      return false;
    } finally {
      clearTimeout(timeout);
    }
  }

  return {
    async capture(event, properties) {
      if (!ALLOWED_EVENTS.has(event)) return false;
      const safeProperties = validateProperties(event, properties);
      if (!safeProperties) return false;
      return send(event, safeProperties);
    },
    async captureWorkflowTrace(record) {
      const safe = workflowTraceProperties(record);
      if (!safe) return false;
      return send("email_shield_workflow_trace", safe.properties, safe.timestamp);
    },
  };
}
