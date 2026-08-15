import express from "express";
import type { Express, Request, Response } from "express";
import type { LocalSecurityManager } from "./localSecurity.js";
import { analyzeMediaAuthenticity, type MediaAuthenticityPort } from "../consumer/mediaAuthenticity.js";

const MAX_MEDIA_BYTES = 25 * 1024 * 1024;

function noStore(res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

export function registerMediaAuthenticityRoute(
  app: Express,
  options: { security: LocalSecurityManager; detector?: MediaAuthenticityPort },
): void {
  app.get(
    "/api/consumer/v1/media/authenticity/status",
    options.security.requireProtectedRead(),
    options.security.requireSameOrigin(),
    (_req: Request, res: Response) => {
      noStore(res);
      res.json({
        schemaVersion: 1,
        available: Boolean(options.detector),
        implementationStatus: options.detector
          ? "vetted_detector_configured"
          : "detector_not_configured",
        supportedInput: {
          imageMaxBytes: 8 * 1024 * 1024,
          audioMaxBytes: 10 * 1024 * 1024,
          videoMaxBytes: 25 * 1024 * 1024,
        },
        privacy: "explicit_user_selected_media_only",
        limitation: options.detector
          ? "A detector result is probabilistic evidence, not proof that media is authentic or manipulated."
          : "No vetted detector is configured in this build. Email Shield will not fabricate a deepfake verdict.",
      });
    },
  );

  app.post(
    "/api/consumer/v1/media/authenticity",
    options.security.requireProtectedRead(),
    options.security.requireSameOrigin(),
    express.raw({ type: "application/octet-stream", limit: MAX_MEDIA_BYTES }),
    async (req: Request, res: Response) => {
      try {
        const kind = req.get("x-email-shield-media-kind");
        if (kind !== "audio" && kind !== "image" && kind !== "video") throw new Error("Media kind must be audio, image or video.");
        const mimeType = req.get("x-email-shield-media-mime")?.trim() ?? "";
        if (!Buffer.isBuffer(req.body) || req.body.length === 0) throw new Error("Media authenticity check requires explicit local media bytes.");
        const result = await analyzeMediaAuthenticity({
          kind,
          bytes: new Uint8Array(req.body),
          mimeType,
          port: options.detector,
        });
        noStore(res);
        res.json(result);
      } catch (error) {
        noStore(res);
        res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
      }
    },
  );
}
