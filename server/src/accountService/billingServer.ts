import express from "express";
import type { NextFunction, Request, Response } from "express";
import type { BillingEntitlementCoordinator, BillingEvidence } from "../billing/billingVerification.js";
import type { SharedAccountFamilyService } from "./service.js";
import type { AccountServiceAuthProof } from "./types.js";

const MAX_BILLING_REQUEST_BYTES = "192kb";
const ALLOWED_REQUEST_FIELDS = new Set(["accountId", "auth", "evidence"]);

function noStore(res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

function safeHeaders(_req: Request, res: Response, next: NextFunction): void {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
  next();
}

function proof(input: unknown): AccountServiceAuthProof {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Billing device authentication proof is required.");
  const value = input as Record<string, unknown>;
  if (Object.keys(value).some((key) => key !== "challengeId" && key !== "signature")) {
    throw new Error("Billing device authentication proof contains unknown fields.");
  }
  if (typeof value.challengeId !== "string" || typeof value.signature !== "string") throw new Error("Billing device authentication proof is invalid.");
  return { challengeId: value.challengeId, signature: value.signature };
}

function accountId(input: unknown): string {
  if (typeof input !== "string" || input.length < 1 || input.length > 128) throw new Error("Email Shield account ID is required for billing verification.");
  return input;
}

export function createAccountBillingServer(
  service: SharedAccountFamilyService,
  coordinator: BillingEntitlementCoordinator | null,
  options: { enabled: boolean } = { enabled: false },
) {
  const router = express.Router();
  router.use(safeHeaders);

  // This route handles only the new operation. Existing snapshot/family/lifecycle
  // challenge operations deliberately fall through to the mature account router.
  router.post("/v1/auth/challenge", express.json({ limit: "32kb", strict: true }), (req, res, next) => {
    const operation = (req.body as { operation?: unknown } | undefined)?.operation;
    if (operation !== "billing:verify") return next();
    try {
      if (!options.enabled || !coordinator) throw new Error("Paid-plan billing verification is currently disabled.");
      const body = req.body as { accountId?: unknown; deviceId?: unknown };
      const challenge = service.issueChallenge(body.accountId, body.deviceId, "billing:verify");
      noStore(res);
      res.json({
        challengeId: challenge.challengeId,
        challenge: challenge.challenge,
        operation: challenge.operation,
        expiresAt: challenge.expiresAt,
      });
    } catch (error) {
      noStore(res);
      res.status(options.enabled ? 400 : 503).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  router.get("/v1/billing/status", (_req, res) => {
    noStore(res);
    res.json({
      schemaVersion: 1,
      enabled: options.enabled && Boolean(coordinator),
      verification: options.enabled && coordinator ? "server_verified_store_evidence" : "disabled_free_only",
      clientSecretsAccepted: false,
    });
  });

  router.post("/v1/billing/verify", express.json({ limit: MAX_BILLING_REQUEST_BYTES, strict: true }), async (req, res) => {
    try {
      if (!options.enabled || !coordinator) throw new Error("Paid-plan billing verification is currently disabled.");
      if (!req.body || typeof req.body !== "object" || Array.isArray(req.body)) throw new Error("Billing verification request is invalid.");
      const body = req.body as Record<string, unknown>;
      if (Object.keys(body).some((key) => !ALLOWED_REQUEST_FIELDS.has(key))) throw new Error("Billing verification request contains unsupported fields.");
      const id = accountId(body.accountId);
      const authenticated = service.authenticate(id, "billing:verify", proof(body.auth));
      if (!body.evidence || typeof body.evidence !== "object" || Array.isArray(body.evidence)) throw new Error("Store billing evidence is required.");
      const result = await coordinator.process(id, body.evidence as BillingEvidence, new AbortController().signal);
      noStore(res);
      res.json({
        verified: true,
        duplicateEvent: result.duplicate,
        entitlement: result.entitlement,
        snapshot: service.snapshot(id, authenticated.device.deviceId),
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      noStore(res);
      const status = /disabled|no .* verifier/i.test(message) ? 503 : /signature|authentication|challenge|device/i.test(message) ? 401 : 400;
      res.status(status).json({ error: message });
    }
  });

  return router;
}
