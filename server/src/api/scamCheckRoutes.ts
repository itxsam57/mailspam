import express, { type Express, type NextFunction, type Request, type Response } from "express";
import type { CommunityNetwork } from "../community/network.js";
import { ConsumerScamCheckError, evaluateConsumerScamCheck } from "../consumer/scamCheck.js";
import {
  ConsumerScamInputError,
  evaluateSubmittedEml,
  evaluateSubmittedImage,
  MAX_SUBMITTED_EML_BYTES,
  type VisualTextExtractor,
} from "../consumer/scamCheckInputs.js";
import { MAX_QR_IMAGE_BYTES } from "../util/qrDecode.js";
import type { LocalSecurityManager } from "./localSecurity.js";

const JSON_LIMIT = "1mb";
const MAX_REQUESTS_PER_MINUTE = 30;

export interface ScamCheckRouteDependencies {
  security: LocalSecurityManager;
  community: Pick<CommunityNetwork, "getVerifiedEntries">;
  visualTextExtractor?: VisualTextExtractor;
}

function noStore(res: Response): void {
  res.setHeader("Cache-Control", "no-store, max-age=0");
}

function publicInputError(error: unknown): { status: number; message: string } {
  if (error instanceof ConsumerScamCheckError || error instanceof ConsumerScamInputError) {
    return { status: error.code === "request_too_large" || error.code === "input_too_large" ? 413 : 400, message: error.message };
  }
  if (error instanceof SyntaxError) return { status: 400, message: "Scam Check request body is invalid." };
  return { status: 500, message: "Scam Check could not complete the local analysis." };
}

function errorHandler(error: unknown, _req: Request, res: Response, _next: NextFunction): void {
  const publicError = publicInputError(error);
  noStore(res);
  res.status(publicError.status).json({ error: publicError.message });
}

function protectedRead(deps: ScamCheckRouteDependencies) {
  return [deps.security.requireProtectedRead(), deps.security.requireSameOrigin()];
}

function routeLimit(deps: ScamCheckRouteDependencies, key: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!deps.security.enforceRouteLimit(req, res, key, MAX_REQUESTS_PER_MINUTE)) return;
    next();
  };
}

/**
 * Register before the desktop server's global 64 KiB JSON parser. Each Scam
 * Check input type owns its own narrow parser/size boundary instead of raising
 * limits for unrelated APIs.
 */
export function registerScamCheckRoutes(app: Express, deps: ScamCheckRouteDependencies): void {
  app.post(
    "/api/scam-check/v1/analyze",
    ...protectedRead(deps),
    routeLimit(deps, "scam-check-json"),
    express.json({ limit: JSON_LIMIT, strict: true, type: "application/json" }),
    (req: Request, res: Response) => {
      try {
        const result = evaluateConsumerScamCheck(req.body, {
          intelligenceEntries: deps.community.getVerifiedEntries(),
        });
        noStore(res);
        res.json(result);
      } catch (error) {
        errorHandler(error, req, res, () => undefined);
      }
    },
  );

  app.post(
    "/api/scam-check/v1/eml",
    ...protectedRead(deps),
    routeLimit(deps, "scam-check-eml"),
    express.raw({ limit: MAX_SUBMITTED_EML_BYTES, type: ["message/rfc822", "application/octet-stream"] }),
    async (req: Request, res: Response) => {
      try {
        if (!Buffer.isBuffer(req.body)) throw new ConsumerScamInputError("invalid_input");
        const result = await evaluateSubmittedEml(req.body, {
          intelligenceEntries: deps.community.getVerifiedEntries(),
        });
        noStore(res);
        res.json(result);
      } catch (error) {
        errorHandler(error, req, res, () => undefined);
      }
    },
  );

  app.post(
    "/api/scam-check/v1/image",
    ...protectedRead(deps),
    routeLimit(deps, "scam-check-image"),
    express.raw({ limit: MAX_QR_IMAGE_BYTES, type: ["image/png", "image/jpeg"] }),
    async (req: Request, res: Response) => {
      try {
        if (!Buffer.isBuffer(req.body)) throw new ConsumerScamInputError("invalid_input");
        const contentType = String(req.get("content-type") ?? "").split(";", 1)[0]!.trim().toLowerCase();
        const result = await evaluateSubmittedImage({
          content: req.body,
          mimeType: contentType,
          name: req.get("x-email-shield-file-name") ?? undefined,
        }, {
          intelligenceEntries: deps.community.getVerifiedEntries(),
        }, {
          visualTextExtractor: deps.visualTextExtractor,
        });
        noStore(res);
        res.json(result);
      } catch (error) {
        errorHandler(error, req, res, () => undefined);
      }
    },
  );

  app.use("/api/scam-check/v1", errorHandler);
}
