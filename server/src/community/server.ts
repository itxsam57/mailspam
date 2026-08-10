import express from "express";
import type { NextFunction, Request, Response } from "express";
import {
  CommunityReportCapacityError,
  CommunityReportRateLimitError,
  CommunityReportValidationError,
  CommunityServiceDisabledError,
} from "./errors.js";
import { communityNetwork, type CommunityNetwork } from "./network.js";
import {
  authorizedMetricsRequest,
  communityRoute,
  configuredMetricsToken,
  discardCommunityDiagnostic,
  CommunityDiagnosticEmitter,
  CommunityOperationalMetrics,
  type CommunityDiagnosticName,
  type CommunityDiagnosticSink,
  type CommunityReportOutcome,
} from "./operationalMetrics.js";
import { MAX_COMMUNITY_REPORT_REQUEST_BYTES } from "./resourceLimits.js";
import { verifyCommunityFeed } from "./signing.js";
import type { CommunityReportSubmission } from "./types.js";

const READY_PROBE_CACHE_MS = 15_000;
const FAILED_PROBE_CACHE_MS = 2_000;

type PublicCommunityErrorCode =
  | "invalid_json"
  | "invalid_report"
  | "rate_limited"
  | "request_too_large"
  | "service_unavailable"
  | "internal_error"
  | "not_found";

interface ExpressBodyError extends Error {
  status?: number;
  statusCode?: number;
  type?: string;
}

export interface CommunityServiceReadiness {
  ready: boolean;
  signedFeedAvailable: boolean;
}

export interface CommunityServiceServerOptions {
  metrics?: CommunityOperationalMetrics;
  metricsToken?: string | null;
  diagnosticSink?: CommunityDiagnosticSink;
  now?: () => number;
}

function sendPublicError(
  res: Response,
  status: number,
  error: PublicCommunityErrorCode,
): Response {
  res.setHeader("Cache-Control", "no-store");
  return res.status(status).json({ error });
}

function isRecordBody(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Readiness must exercise the same read-only aggregate/sign/verify path that
 * serves the public feed. Internal failure details are deliberately collapsed
 * to booleans because this result is exposed on the unauthenticated health
 * endpoint.
 */
export function inspectCommunityServiceReadiness(
  network: CommunityNetwork,
): CommunityServiceReadiness {
  if (!network.serverEnabled) return { ready: false, signedFeedAvailable: false };
  try {
    const info = network.publicInfo();
    const document = network.signedFeed();
    const signedFeedAvailable = verifyCommunityFeed(document, [info.publicKey]) !== null;
    return { ready: signedFeedAvailable, signedFeedAvailable };
  } catch {
    return { ready: false, signedFeedAvailable: false };
  }
}

/**
 * Dedicated public service surface. It deliberately does not mount the Email
 * Shield desktop dashboard, mailbox account APIs, scan workers, provider
 * credentials, or destructive mailbox actions.
 */
export function createCommunityServiceServer(
  network: CommunityNetwork = communityNetwork,
  options: CommunityServiceServerOptions = {},
) {
  const app = express();
  const now = options.now ?? Date.now;
  const metrics = options.metrics ?? new CommunityOperationalMetrics(now);
  const metricsToken = configuredMetricsToken(
    options.metricsToken === undefined
      ? process.env.EMAIL_SHIELD_COMMUNITY_METRICS_TOKEN
      : options.metricsToken,
  );
  const diagnosticSink = options.diagnosticSink ?? discardCommunityDiagnostic;
  const diagnosticEmitter = new CommunityDiagnosticEmitter(metrics, diagnosticSink, now);
  const diagnostic = (
    event: CommunityDiagnosticName,
    severity: "warning" | "error" = "warning",
  ) => diagnosticEmitter.emit(event, severity);
  const recordReportFailure = (
    outcome: CommunityReportOutcome,
    event: CommunityDiagnosticName,
  ) => {
    metrics.recordReport(outcome);
    diagnostic(event, outcome === "internal_error" ? "error" : "warning");
  };
  const reportErrorResponse = (res: Response, error: unknown): Response => {
    if (error instanceof CommunityReportValidationError) {
      recordReportFailure("invalid", "invalid_report");
      return sendPublicError(res, 400, "invalid_report");
    }
    if (error instanceof CommunityReportRateLimitError) {
      recordReportFailure("rate_limited", "rate_limited");
      return sendPublicError(res, 429, "rate_limited");
    }
    if (error instanceof CommunityReportCapacityError) {
      recordReportFailure("capacity_rejected", "capacity_rejected");
      return sendPublicError(res, 503, "service_unavailable");
    }
    if (error instanceof CommunityServiceDisabledError) {
      recordReportFailure("service_unavailable", "service_unavailable");
      return sendPublicError(res, 503, "service_unavailable");
    }
    recordReportFailure("internal_error", "internal_error");
    return sendPublicError(res, 503, "service_unavailable");
  };

  let readinessCache: { expiresAt: number; value: CommunityServiceReadiness } | null = null;
  const readiness = (): CommunityServiceReadiness => {
    const currentTime = now();
    if (readinessCache && currentTime < readinessCache.expiresAt) return readinessCache.value;
    const value = inspectCommunityServiceReadiness(network);
    readinessCache = {
      value,
      expiresAt: currentTime + (value.ready ? READY_PROBE_CACHE_MS : FAILED_PROBE_CACHE_MS),
    };
    if (!value.ready) diagnostic("readiness_failed", "error");
    return value;
  };

  app.disable("x-powered-by");
  app.use((req: Request, res: Response, next: NextFunction) => {
    const startedAt = now();
    let recorded = false;
    const record = () => {
      if (recorded) return;
      recorded = true;
      metrics.finishRequest(communityRoute(req.method, req.path), res.statusCode, now() - startedAt);
    };
    metrics.beginRequest();
    res.once("finish", record);
    res.once("close", record);
    next();
  });
  app.use(express.json({ limit: MAX_COMMUNITY_REPORT_REQUEST_BYTES }));

  app.get("/health", (_req: Request, res: Response) => {
    const state = readiness();
    res.setHeader("Cache-Control", "no-store");
    res.status(state.ready ? 200 : 503).json({
      service: "email-shield-community",
      ...state,
    });
  });

  app.get("/api/community/v1/status", (_req: Request, res: Response) => {
    try {
      const info = network.publicInfo();
      res.json({
        aggregationServerEnabled: info.enabled,
        keyId: info.enabled ? info.keyId : null,
        stats: info.enabled ? info.stats : null,
      });
    } catch {
      diagnostic("service_unavailable", "error");
      sendPublicError(res, 503, "service_unavailable");
    }
  });

  app.post("/api/community/v1/report", (req: Request, res: Response) => {
    if (!isRecordBody(req.body)) {
      recordReportFailure("invalid", "invalid_report");
      return sendPublicError(res, 400, "invalid_report");
    }
    try {
      const receipt = network.acceptExternalReport(req.body as unknown as CommunityReportSubmission);
      metrics.recordReport(receipt.duplicate ? "duplicate" : "accepted");
      res.setHeader("Cache-Control", "no-store");
      res.json(receipt);
    } catch (error) {
      reportErrorResponse(res, error);
    }
  });

  app.get("/api/community/v1/feed", (_req: Request, res: Response) => {
    try {
      const document = network.signedFeed();
      res.setHeader("Cache-Control", "public, max-age=300");
      res.json(document);
    } catch {
      diagnostic("service_unavailable", "error");
      sendPublicError(res, 503, "service_unavailable");
    }
  });

  app.get("/api/community/v1/public-key", (_req: Request, res: Response) => {
    try {
      const info = network.publicInfo();
      if (!info.enabled) return sendPublicError(res, 503, "service_unavailable");
      res.setHeader("Cache-Control", "public, max-age=3600");
      return res.json(info);
    } catch {
      diagnostic("service_unavailable", "error");
      return sendPublicError(res, 503, "service_unavailable");
    }
  });

  app.get("/metrics", (req: Request, res: Response) => {
    if (!metricsToken) return sendPublicError(res, 404, "not_found");
    if (!authorizedMetricsRequest(req.header("authorization"), metricsToken)) {
      diagnostic("metrics_auth_failed");
      res.setHeader("WWW-Authenticate", 'Bearer realm="email-shield-community-metrics"');
      return sendPublicError(res, 401, "not_found");
    }
    let aggregate = null;
    try {
      aggregate = network.publicInfo().stats;
    } catch {}
    res.setHeader("Cache-Control", "no-store");
    res.type("text/plain; version=0.0.4; charset=utf-8");
    return res.send(metrics.renderPrometheus(readiness(), aggregate));
  });

  app.use((_req: Request, res: Response) => {
    sendPublicError(res, 404, "not_found");
  });

  // Keep Express/body-parser diagnostics, stack traces and filesystem details
  // out of the unauthenticated service boundary.
  app.use((error: unknown, req: Request, res: Response, _next: NextFunction) => {
    const bodyError = error as ExpressBodyError;
    const status = bodyError?.status ?? bodyError?.statusCode;
    if (status === 413 || bodyError?.type === "entity.too.large") {
      if (communityRoute(req.method, req.path) === "report") metrics.recordReport("invalid");
      diagnostic("request_too_large");
      return sendPublicError(res, 413, "request_too_large");
    }
    if (status === 400 && (bodyError instanceof SyntaxError || bodyError?.type === "entity.parse.failed")) {
      if (communityRoute(req.method, req.path) === "report") metrics.recordReport("invalid");
      diagnostic("invalid_json");
      return sendPublicError(res, 400, "invalid_json");
    }
    diagnostic("internal_error", "error");
    return sendPublicError(res, 500, "internal_error");
  });

  return app;
}
