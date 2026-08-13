import express from "express";
import type { NextFunction, Request, Response } from "express";
import type { BillingEntitlementCoordinator, BillingEvidence } from "../billing/billingVerification.js";
import type { SharedAccountFamilyService } from "./service.js";
import type { AccountServiceAuthProof } from "./types.js";

const MAX_BILLING_REQUEST_BYTES = "192kb";
const ALLOWED_REQUEST_FIELDS = new Set(["accountId", "auth", "evidence"]);
const BILLING_RATE_TABLE_MAX_KEYS = 20_000;
const BILLING_CHALLENGE_LIMIT = 30;
const BILLING_VERIFY_LIMIT = 12;
const BILLING_RATE_WINDOW_MS = 15 * 60_000;
const BILLING_VERIFICATION_DEADLINE_MS = 20_000;

interface BillingRateState {
  startedAt: number;
  count: number;
  windowMs: number;
}

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

function trustedClientAddress(req: Request, trustProxy: boolean): string {
  if (trustProxy) {
    const forwarded = req.headers["x-forwarded-for"];
    const candidate = Array.isArray(forwarded) ? forwarded[0] : forwarded?.split(",", 1)[0];
    const normalized = candidate?.trim();
    if (normalized) return normalized.slice(0, 128);
  }
  return (req.socket.remoteAddress || "unknown").slice(0, 128);
}

export function createAccountBillingServer(
  service: SharedAccountFamilyService,
  coordinator: BillingEntitlementCoordinator | null,
  options: { enabled: boolean; trustProxy?: boolean } = { enabled: false },
) {
  const router = express.Router();
  router.use(safeHeaders);

  const rate = new Map<string, BillingRateState>();
  const allowBillingRequest = (req: Request, res: Response, bucket: string, max: number, windowMs: number): boolean => {
    const now = Date.now();
    const key = `${bucket}:${trustedClientAddress(req, options.trustProxy === true)}`;
    let state = rate.get(key);
    if (!state || now - state.startedAt >= state.windowMs) {
      if (!state && rate.size >= BILLING_RATE_TABLE_MAX_KEYS) {
        for (const [candidate, candidateState] of rate) {
          if (now - candidateState.startedAt >= candidateState.windowMs) rate.delete(candidate);
        }
        if (rate.size >= BILLING_RATE_TABLE_MAX_KEYS) {
          noStore(res);
          res.setHeader("Retry-After", "60");
          res.status(429).json({ error: "Billing verification is temporarily rate limited." });
          return false;
        }
      }
      state = { startedAt: now, count: 0, windowMs };
    }
    state.count += 1;
    rate.set(key, state);
    if (state.count > max) {
      noStore(res);
      res.setHeader("Retry-After", String(Math.max(1, Math.ceil((state.startedAt + state.windowMs - now) / 1000))));
      res.status(429).json({ error: "Billing verification rate limit exceeded." });
      return false;
    }
    return true;
  };

  // This route handles only the new operation. Existing snapshot/family/lifecycle
  // challenge operations deliberately fall through to the mature account router.
  router.post("/v1/auth/challenge", express.json({ limit: "32kb", strict: true }), (req, res, next) => {
    const operation = (req.body as { operation?: unknown } | undefined)?.operation;
    if (operation !== "billing:verify") return next();
    if (!allowBillingRequest(req, res, "challenge", BILLING_CHALLENGE_LIMIT, BILLING_RATE_WINDOW_MS)) return;
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
      rateLimits: {
        challengePer15Minutes: BILLING_CHALLENGE_LIMIT,
        verificationPer15Minutes: BILLING_VERIFY_LIMIT,
      },
    });
  });

  router.post(
    "/v1/billing/verify",
    (req, res, next) => {
      if (!allowBillingRequest(req, res, "verify", BILLING_VERIFY_LIMIT, BILLING_RATE_WINDOW_MS)) return;
      next();
    },
    express.json({ limit: MAX_BILLING_REQUEST_BYTES, strict: true }),
    async (req, res) => {
      try {
        if (!options.enabled || !coordinator) throw new Error("Paid-plan billing verification is currently disabled.");
        if (!req.body || typeof req.body !== "object" || Array.isArray(req.body)) throw new Error("Billing verification request is invalid.");
        const body = req.body as Record<string, unknown>;
        if (Object.keys(body).some((key) => !ALLOWED_REQUEST_FIELDS.has(key))) throw new Error("Billing verification request contains unsupported fields.");
        const id = accountId(body.accountId);
        const authenticated = service.authenticate(id, "billing:verify", proof(body.auth));
        if (!body.evidence || typeof body.evidence !== "object" || Array.isArray(body.evidence)) throw new Error("Store billing evidence is required.");
        const deadline = AbortSignal.timeout(BILLING_VERIFICATION_DEADLINE_MS);
        const result = await coordinator.process(id, body.evidence as BillingEvidence, deadline);
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
    },
  );

  return router;
}
