import express from "express";
import type { NextFunction, Request, Response } from "express";
import {
  CommunityReportCapacityError,
  CommunityReportRateLimitError,
  CommunityReportValidationError,
  CommunityServiceDisabledError,
} from "./errors.js";
import { communityNetwork, type CommunityNetwork } from "./network.js";
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

function sendPublicError(
  res: Response,
  status: number,
  error: PublicCommunityErrorCode,
): Response {
  res.setHeader("Cache-Control", "no-store");
  return res.status(status).json({ error });
}

function reportErrorResponse(res: Response, error: unknown): Response {
  if (error instanceof CommunityReportValidationError) return sendPublicError(res, 400, "invalid_report");
  if (error instanceof CommunityReportRateLimitError) return sendPublicError(res, 429, "rate_limited");
  if (error instanceof CommunityReportCapacityError || error instanceof CommunityServiceDisabledError) {
    return sendPublicError(res, 503, "service_unavailable");
  }
  return sendPublicError(res, 503, "service_unavailable");
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
) {
  const app = express();
  let readinessCache: { expiresAt: number; value: CommunityServiceReadiness } | null = null;
  const readiness = (): CommunityServiceReadiness => {
    const now = Date.now();
    if (readinessCache && now < readinessCache.expiresAt) return readinessCache.value;
    const value = inspectCommunityServiceReadiness(network);
    readinessCache = {
      value,
      expiresAt: now + (value.ready ? READY_PROBE_CACHE_MS : FAILED_PROBE_CACHE_MS),
    };
    return value;
  };

  app.disable("x-powered-by");
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
      sendPublicError(res, 503, "service_unavailable");
    }
  });

  app.post("/api/community/v1/report", (req: Request, res: Response) => {
    if (!isRecordBody(req.body)) return sendPublicError(res, 400, "invalid_report");
    try {
      const receipt = network.acceptExternalReport(req.body as unknown as CommunityReportSubmission);
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
      return sendPublicError(res, 503, "service_unavailable");
    }
  });

  app.use((_req: Request, res: Response) => {
    sendPublicError(res, 404, "not_found");
  });

  // Keep Express/body-parser diagnostics, stack traces and filesystem details
  // out of the unauthenticated service boundary.
  app.use((error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    const bodyError = error as ExpressBodyError;
    const status = bodyError?.status ?? bodyError?.statusCode;
    if (status === 413 || bodyError?.type === "entity.too.large") {
      return sendPublicError(res, 413, "request_too_large");
    }
    if (status === 400 && (bodyError instanceof SyntaxError || bodyError?.type === "entity.parse.failed")) {
      return sendPublicError(res, 400, "invalid_json");
    }
    return sendPublicError(res, 500, "internal_error");
  });

  return app;
}
