import express from "express";
import type { Request, Response } from "express";
import { communityNetwork, type CommunityNetwork } from "./network.js";
import { MAX_COMMUNITY_REPORT_REQUEST_BYTES } from "./resourceLimits.js";
import { verifyCommunityFeed } from "./signing.js";
import type { CommunityReportSubmission } from "./types.js";

const READY_PROBE_CACHE_MS = 15_000;
const FAILED_PROBE_CACHE_MS = 2_000;

export interface CommunityServiceReadiness {
  ready: boolean;
  signedFeedAvailable: boolean;
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
    const info = network.publicInfo();
    res.json({
      aggregationServerEnabled: info.enabled,
      keyId: info.enabled ? info.keyId : null,
      stats: info.enabled ? info.stats : null,
    });
  });

  app.post("/api/community/v1/report", (req: Request, res: Response) => {
    try {
      const receipt = network.acceptExternalReport(req.body as CommunityReportSubmission);
      res.setHeader("Cache-Control", "no-store");
      res.json(receipt);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const status = message.includes("disabled") ? 503 : message.includes("rate limit") ? 429 : 400;
      res.status(status).json({ error: message });
    }
  });

  app.get("/api/community/v1/feed", (_req: Request, res: Response) => {
    try {
      res.setHeader("Cache-Control", "public, max-age=300");
      res.json(network.signedFeed());
    } catch (error) {
      res.status(503).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.get("/api/community/v1/public-key", (_req: Request, res: Response) => {
    const info = network.publicInfo();
    if (!info.enabled) return res.status(503).json({ error: "Community aggregation service is disabled." });
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.json(info);
  });

  app.use((_req: Request, res: Response) => {
    res.status(404).json({ error: "Not found" });
  });

  return app;
}
