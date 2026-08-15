import type { Express, Response } from "express";
import { analyzeShoppingSafety } from "../consumer/shoppingSafety.js";

function noStore(res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

/**
 * Explicit user-submitted storefront analysis only.
 *
 * The canonical consumer desktop composition mounts this after the protected
 * /api/consumer security boundary and bounded JSON parser. Nothing here crawls
 * browsing history, purchases, cookies, credentials or arbitrary storefronts.
 */
export function registerShoppingSafetyRoute(app: Express): void {
  app.post("/api/consumer/v1/shopping/check", (req, res) => {
    try {
      const result = analyzeShoppingSafety(req.body);
      noStore(res);
      res.json(result);
    } catch (error) {
      noStore(res);
      res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });
}
