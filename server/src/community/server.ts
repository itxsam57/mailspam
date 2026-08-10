import express from "express";
import type { Request, Response } from "express";
import { communityNetwork, type CommunityNetwork } from "./network.js";
import { MAX_COMMUNITY_REPORT_REQUEST_BYTES } from "./resourceLimits.js";
import type { CommunityReportSubmission } from "./types.js";

/**
 * Dedicated public service surface. It deliberately does not mount the Email
 * Shield desktop dashboard, mailbox account APIs, scan workers, provider
 * credentials, or destructive mailbox actions.
 */
export function createCommunityServiceServer(
  network: CommunityNetwork = communityNetwork,
) {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: MAX_COMMUNITY_REPORT_REQUEST_BYTES }));

  app.get("/health", (_req: Request, res: Response) => {
    res.json({
      service: "email-shield-community",
      ready: network.serverEnabled,
      signedFeedAvailable: network.serverEnabled,
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
