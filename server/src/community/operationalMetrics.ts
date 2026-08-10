import { timingSafeEqual } from "node:crypto";

export type CommunityRoute =
  | "health"
  | "status"
  | "report"
  | "feed"
  | "public_key"
  | "metrics"
  | "not_found";

export type CommunityReportOutcome =
  | "accepted"
  | "duplicate"
  | "invalid"
  | "rate_limited"
  | "capacity_rejected"
  | "service_unavailable"
  | "internal_error";

export type CommunityDiagnosticName =
  | "readiness_failed"
  | "invalid_json"
  | "invalid_report"
  | "rate_limited"
  | "capacity_rejected"
  | "service_unavailable"
  | "request_too_large"
  | "internal_error"
  | "metrics_auth_failed";

export interface CommunityDiagnosticEvent {
  schemaVersion: 1;
  timestamp: string;
  component: "email-shield-community";
  severity: "warning" | "error";
  event: CommunityDiagnosticName;
}

export type CommunityDiagnosticSink = (event: CommunityDiagnosticEvent) => void;
export const COMMUNITY_DIAGNOSTIC_EMIT_INTERVAL_MS = 30_000;
export const MAX_COMMUNITY_METRICS_TOKEN_BYTES = 4 * 1024;

export interface CommunityAggregateMetrics {
  campaigns: number;
  warnings: number;
  confirmed: number;
}

export interface CommunityMetricsSnapshot {
  uptimeSeconds: number;
  activeRequests: number;
  requests: Record<string, number>;
  requestDurationMilliseconds: Record<CommunityRoute, number>;
  reportOutcomes: Record<CommunityReportOutcome, number>;
  diagnostics: Record<CommunityDiagnosticName, number>;
}

const ROUTES: CommunityRoute[] = ["health", "status", "report", "feed", "public_key", "metrics", "not_found"];
const STATUS_CLASSES = ["2xx", "4xx", "5xx"] as const;
const REPORT_OUTCOMES: CommunityReportOutcome[] = [
  "accepted",
  "duplicate",
  "invalid",
  "rate_limited",
  "capacity_rejected",
  "service_unavailable",
  "internal_error",
];
const DIAGNOSTICS: CommunityDiagnosticName[] = [
  "readiness_failed",
  "invalid_json",
  "invalid_report",
  "rate_limited",
  "capacity_rejected",
  "service_unavailable",
  "request_too_large",
  "internal_error",
  "metrics_auth_failed",
];

function zeroRecord<T extends string>(keys: readonly T[]): Record<T, number> {
  return Object.fromEntries(keys.map((key) => [key, 0])) as Record<T, number>;
}

function statusClass(statusCode: number): "2xx" | "4xx" | "5xx" {
  if (statusCode >= 500) return "5xx";
  if (statusCode >= 400) return "4xx";
  return "2xx";
}

function metricLine(name: string, value: number, labels?: Record<string, string>): string {
  const suffix = labels
    ? `{${Object.entries(labels).map(([key, item]) => `${key}="${item}"`).join(",")}}`
    : "";
  return `${name}${suffix} ${Number.isFinite(value) ? value : 0}`;
}

/** Fixed-cardinality, aggregate-only process metrics for the public community service. */
export class CommunityOperationalMetrics {
  private readonly startedAt: number;
  private activeRequests = 0;
  private readonly requests = new Map<string, number>();
  private readonly requestDurationMilliseconds = zeroRecord(ROUTES);
  private readonly reportOutcomes = zeroRecord(REPORT_OUTCOMES);
  private readonly diagnostics = zeroRecord(DIAGNOSTICS);

  constructor(private readonly now: () => number = Date.now) {
    this.startedAt = now();
  }

  beginRequest(): void {
    this.activeRequests += 1;
  }

  finishRequest(route: CommunityRoute, statusCode: number, durationMilliseconds: number): void {
    this.activeRequests = Math.max(0, this.activeRequests - 1);
    const key = `${route}:${statusClass(statusCode)}`;
    this.requests.set(key, (this.requests.get(key) ?? 0) + 1);
    this.requestDurationMilliseconds[route] += Math.max(0, durationMilliseconds);
  }

  recordReport(outcome: CommunityReportOutcome): void {
    this.reportOutcomes[outcome] += 1;
  }

  recordDiagnostic(name: CommunityDiagnosticName): void {
    this.diagnostics[name] += 1;
  }

  snapshot(): CommunityMetricsSnapshot {
    const requests: Record<string, number> = {};
    for (const route of ROUTES) {
      for (const result of STATUS_CLASSES) requests[`${route}:${result}`] = this.requests.get(`${route}:${result}`) ?? 0;
    }
    return {
      uptimeSeconds: Math.max(0, (this.now() - this.startedAt) / 1000),
      activeRequests: this.activeRequests,
      requests,
      requestDurationMilliseconds: { ...this.requestDurationMilliseconds },
      reportOutcomes: { ...this.reportOutcomes },
      diagnostics: { ...this.diagnostics },
    };
  }

  renderPrometheus(
    readiness: { ready: boolean; signedFeedAvailable: boolean },
    aggregate: CommunityAggregateMetrics | null,
  ): string {
    const snapshot = this.snapshot();
    const lines = [
      "# HELP email_shield_community_ready Whether the real aggregate/sign/verify readiness path is healthy.",
      "# TYPE email_shield_community_ready gauge",
      metricLine("email_shield_community_ready", readiness.ready ? 1 : 0),
      "# HELP email_shield_community_signed_feed_available Whether a signed feed is currently verifiable.",
      "# TYPE email_shield_community_signed_feed_available gauge",
      metricLine("email_shield_community_signed_feed_available", readiness.signedFeedAvailable ? 1 : 0),
      "# HELP email_shield_community_active_requests Current in-process HTTP requests.",
      "# TYPE email_shield_community_active_requests gauge",
      metricLine("email_shield_community_active_requests", snapshot.activeRequests),
      "# HELP email_shield_community_uptime_seconds Process metrics uptime.",
      "# TYPE email_shield_community_uptime_seconds gauge",
      metricLine("email_shield_community_uptime_seconds", snapshot.uptimeSeconds),
      "# HELP email_shield_community_requests_total Requests by fixed route and status class.",
      "# TYPE email_shield_community_requests_total counter",
    ];
    for (const route of ROUTES) {
      for (const result of STATUS_CLASSES) {
        lines.push(metricLine("email_shield_community_requests_total", snapshot.requests[`${route}:${result}`] ?? 0, { route, result }));
      }
    }
    lines.push(
      "# HELP email_shield_community_request_duration_seconds_sum Cumulative request time by fixed route.",
      "# TYPE email_shield_community_request_duration_seconds_sum counter",
    );
    for (const route of ROUTES) {
      lines.push(metricLine(
        "email_shield_community_request_duration_seconds_sum",
        snapshot.requestDurationMilliseconds[route] / 1000,
        { route },
      ));
    }
    lines.push(
      "# HELP email_shield_community_reports_total Report outcomes with fixed privacy-safe labels.",
      "# TYPE email_shield_community_reports_total counter",
    );
    for (const outcome of REPORT_OUTCOMES) {
      lines.push(metricLine("email_shield_community_reports_total", snapshot.reportOutcomes[outcome], { outcome }));
    }
    lines.push(
      "# HELP email_shield_community_diagnostics_total Structured operational events with fixed privacy-safe labels.",
      "# TYPE email_shield_community_diagnostics_total counter",
    );
    for (const event of DIAGNOSTICS) {
      lines.push(metricLine("email_shield_community_diagnostics_total", snapshot.diagnostics[event], { event }));
    }
    lines.push(
      "# HELP email_shield_community_aggregate_available Whether bounded aggregate counts were readable.",
      "# TYPE email_shield_community_aggregate_available gauge",
      metricLine("email_shield_community_aggregate_available", aggregate ? 1 : 0),
    );
    if (aggregate) {
      lines.push(
        "# HELP email_shield_community_campaigns Current retained campaign counts by fixed state.",
        "# TYPE email_shield_community_campaigns gauge",
        metricLine("email_shield_community_campaigns", aggregate.campaigns, { state: "all" }),
        metricLine("email_shield_community_campaigns", aggregate.warnings, { state: "warning" }),
        metricLine("email_shield_community_campaigns", aggregate.confirmed, { state: "confirmed" }),
      );
    }
    return `${lines.join("\n")}\n`;
  }
}

export function communityRoute(method: string, path: string): CommunityRoute {
  if (method === "GET" && path === "/health") return "health";
  if (method === "GET" && path === "/api/community/v1/status") return "status";
  if (method === "POST" && path === "/api/community/v1/report") return "report";
  if (method === "GET" && path === "/api/community/v1/feed") return "feed";
  if (method === "GET" && path === "/api/community/v1/public-key") return "public_key";
  if (method === "GET" && path === "/metrics") return "metrics";
  return "not_found";
}

export function configuredMetricsToken(value: string | undefined | null): string | null {
  const token = value?.trim() ?? "";
  if (!token) return null;
  const bytes = Buffer.byteLength(token, "utf8");
  if (bytes < 32 || bytes > MAX_COMMUNITY_METRICS_TOKEN_BYTES) {
    throw new Error(`EMAIL_SHIELD_COMMUNITY_METRICS_TOKEN must contain between 32 and ${MAX_COMMUNITY_METRICS_TOKEN_BYTES} bytes.`);
  }
  return token;
}

export function authorizedMetricsRequest(authorization: string | undefined, expectedToken: string): boolean {
  const prefix = "Bearer ";
  if (!authorization?.startsWith(prefix)) return false;
  const supplied = Buffer.from(authorization.slice(prefix.length), "utf8");
  const expected = Buffer.from(expectedToken, "utf8");
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

export function emitCommunityDiagnostic(
  metrics: CommunityOperationalMetrics,
  sink: CommunityDiagnosticSink,
  event: CommunityDiagnosticName,
  severity: "warning" | "error" = "warning",
  now: () => number = Date.now,
): void {
  metrics.recordDiagnostic(event);
  try {
    sink({
      schemaVersion: 1,
      timestamp: new Date(now()).toISOString(),
      component: "email-shield-community",
      severity,
      event,
    });
  } catch {
    // Diagnostics must never alter the public request result or expose sink failures.
  }
}

/** Counts every event while bounding JSON-line emission to one line per event type per interval. */
export class CommunityDiagnosticEmitter {
  private readonly lastEmittedAt = new Map<CommunityDiagnosticName, number>();

  constructor(
    private readonly metrics: CommunityOperationalMetrics,
    private readonly sink: CommunityDiagnosticSink,
    private readonly now: () => number = Date.now,
    private readonly intervalMs: number = COMMUNITY_DIAGNOSTIC_EMIT_INTERVAL_MS,
  ) {
    if (!Number.isSafeInteger(intervalMs) || intervalMs < 1) {
      throw new Error("Community diagnostic interval must be a positive safe integer.");
    }
  }

  emit(event: CommunityDiagnosticName, severity: "warning" | "error" = "warning"): void {
    this.metrics.recordDiagnostic(event);
    const currentTime = this.now();
    const last = this.lastEmittedAt.get(event);
    if (last !== undefined && currentTime - last < this.intervalMs) return;
    this.lastEmittedAt.set(event, currentTime);
    try {
      this.sink({
        schemaVersion: 1,
        timestamp: new Date(currentTime).toISOString(),
        component: "email-shield-community",
        severity,
        event,
      });
    } catch {
      // Diagnostics must never alter the public request result or expose sink failures.
    }
  }
}

export const discardCommunityDiagnostic: CommunityDiagnosticSink = () => {};

export function createJsonLineCommunityDiagnosticSink(
  write: (line: string) => void,
): CommunityDiagnosticSink {
  return (event) => write(`${JSON.stringify(event)}\n`);
}
