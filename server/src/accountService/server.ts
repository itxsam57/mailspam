import { timingSafeEqual } from "node:crypto";
import express from "express";
import type { NextFunction, Request, Response } from "express";
import type { DevicePublicIdentity, VerifiedEntitlement } from "../platform/accountFamilyTypes.js";
import { SharedAccountFamilyService } from "./service.js";
import type {
  AccountRegistrationInput,
  AccountServiceAuthProof,
  AccountServiceOperation,
} from "./types.js";

const FORBIDDEN_MAIL_FIELDS = new Set([
  "subject",
  "body",
  "bodytext",
  "rawbody",
  "htmlsignals",
  "textpreview",
  "providernativeid",
  "messageid",
  "senderaddress",
  "mailboxaddress",
  "recipientaddress",
  "rawurl",
  "attachmentbody",
  "apppassword",
  "accesstoken",
  "refreshtoken",
  "oauthcode",
]);

const OPERATIONS = new Set<AccountServiceOperation>([
  "snapshot",
  "family:create",
  "family:invite",
  "family:join",
  "family:leave",
  "family:strict",
  "family:remove-member",
  "family:threat",
]);

interface RateState { startedAt: number; count: number; }

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

function inspectForbiddenFields(value: unknown, depth = 0): void {
  if (depth > 8) throw new Error("Account service request nesting is too deep.");
  if (Array.isArray(value)) {
    if (value.length > 128) throw new Error("Account service request array is too large.");
    for (const item of value) inspectForbiddenFields(item, depth + 1);
    return;
  }
  if (!value || typeof value !== "object") return;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length > 64) throw new Error("Account service request contains too many fields.");
  for (const [key, child] of Object.entries(record)) {
    if (FORBIDDEN_MAIL_FIELDS.has(key.toLowerCase())) {
      throw new Error(`Account/family synchronization rejects mailbox field ${key}.`);
    }
    inspectForbiddenFields(child, depth + 1);
  }
}

function accountId(body: unknown): string {
  const value = (body as { accountId?: unknown })?.accountId;
  if (typeof value !== "string") throw new Error("Email Shield account ID is required.");
  return value;
}

function authProof(body: unknown): AccountServiceAuthProof {
  const value = (body as { auth?: unknown })?.auth;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Device authentication proof is required.");
  const proof = value as Record<string, unknown>;
  if (Object.keys(proof).some((key) => !["challengeId", "signature"].includes(key))) throw new Error("Device authentication proof contains unknown fields.");
  if (typeof proof.challengeId !== "string" || typeof proof.signature !== "string") throw new Error("Device authentication proof is invalid.");
  return { challengeId: proof.challengeId, signature: proof.signature };
}

function errorStatus(message: string): number {
  if (/unknown|not registered|signature|authentication|recovery proof|device proof/i.test(message)) return 401;
  if (/already|seat|member|owner|family|entitlement|expired|revoked/i.test(message)) return 409;
  if (/capacity|temporarily full/i.test(message)) return 503;
  return 400;
}

function adminAuthorized(candidate: string, expected: string | undefined): boolean {
  if (!expected || expected.length < 32 || candidate.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(candidate, "utf8"), Buffer.from(expected, "utf8"));
}

export function createAccountServiceServer(service: SharedAccountFamilyService, options: {
  adminToken?: string;
  allowDevelopmentEntitlements?: boolean;
  trustProxy?: boolean;
} = {}) {
  const app = express();
  app.disable("x-powered-by");
  if (options.trustProxy) app.set("trust proxy", 1);
  app.use(safeHeaders);
  app.use(express.json({ limit: "32kb", strict: true }));

  const rate = new Map<string, RateState>();
  const limited = (bucket: string, max: number, windowMs: number) => (req: Request, res: Response, next: NextFunction) => {
    const now = Date.now();
    const key = `${bucket}:${req.ip || req.socket.remoteAddress || "unknown"}`;
    const previous = rate.get(key);
    const state = !previous || now - previous.startedAt >= windowMs ? { startedAt: now, count: 0 } : previous;
    state.count += 1;
    rate.set(key, state);
    if (rate.size > 20_000) {
      for (const [candidate, value] of rate) if (now - value.startedAt >= Math.max(windowMs, 60_000)) rate.delete(candidate);
    }
    if (state.count > max) {
      noStore(res);
      return res.status(429).json({ error: "Account service rate limit exceeded." });
    }
    next();
  };

  app.use((req, res, next) => {
    try {
      if (req.body !== undefined) inspectForbiddenFields(req.body);
      next();
    } catch (error) {
      noStore(res);
      res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.get("/v1/status", (_req, res) => {
    noStore(res);
    res.json({
      service: "email-shield-account-family",
      schemaVersion: 1,
      persistent: service.persistent(),
      mailContentAccepted: false,
      auth: "device-signed-single-use-challenge",
    });
  });

  app.post("/v1/accounts/register", limited("register", 10, 60 * 60_000), (req, res) => {
    try {
      const body = req.body as AccountRegistrationInput;
      const snapshot = service.registerAccount(body);
      noStore(res);
      res.status(201).json({ snapshot });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      noStore(res);
      res.status(errorStatus(message)).json({ error: message });
    }
  });

  app.post("/v1/accounts/recover", limited("recover", 5, 15 * 60_000), (req, res) => {
    try {
      const body = req.body as { username?: unknown; recoveryCode?: unknown; device?: unknown; deviceProof?: unknown };
      if (
        typeof body.username !== "string" ||
        typeof body.recoveryCode !== "string" ||
        !body.device || typeof body.device !== "object" ||
        typeof body.deviceProof !== "string"
      ) {
        throw new Error("Username, recovery code, new device identity and device proof are required.");
      }
      const result = service.recoverAccount({
        username: body.username,
        recoveryCode: body.recoveryCode,
        device: body.device as DevicePublicIdentity,
        deviceProof: body.deviceProof,
      });
      noStore(res);
      res.json({
        ...result,
        recoveryCodeNotice: "Recovery succeeded. The previous recovery code is invalid; store the rotated replacement securely.",
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      noStore(res);
      res.status(errorStatus(message)).json({ error: message });
    }
  });

  app.post("/v1/auth/challenge", limited("challenge", 30, 60_000), (req, res) => {
    try {
      const body = req.body as { accountId?: unknown; deviceId?: unknown; operation?: unknown };
      if (typeof body.operation !== "string" || !OPERATIONS.has(body.operation as AccountServiceOperation)) throw new Error("Account service operation is invalid.");
      const challenge = service.issueChallenge(body.accountId, body.deviceId, body.operation as AccountServiceOperation);
      noStore(res);
      res.json({
        challengeId: challenge.challengeId,
        challenge: challenge.challenge,
        operation: challenge.operation,
        expiresAt: challenge.expiresAt,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      noStore(res);
      res.status(errorStatus(message)).json({ error: message });
    }
  });

  const authenticated = (
    operation: AccountServiceOperation,
    handler: (req: Request, res: Response, context: { accountId: string; deviceId: string }) => void | Promise<void>,
  ) => [limited("authenticated", 180, 60_000), async (req: Request, res: Response) => {
    try {
      const id = accountId(req.body);
      const authenticatedDevice = service.authenticate(id, operation, authProof(req.body));
      await handler(req, res, { accountId: id, deviceId: authenticatedDevice.device.deviceId });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      noStore(res);
      res.status(errorStatus(message)).json({ error: message });
    }
  }] as const;

  app.post("/v1/sync/snapshot", ...authenticated("snapshot", async (_req, res, context) => {
    noStore(res);
    res.json({
      schemaVersion: 1,
      account: service.snapshot(context.accountId, context.deviceId),
      familyThreats: service.familyThreatSnapshot(context.accountId),
      synchronizedAt: Date.now(),
    });
  }));

  app.post("/v1/family/create", ...authenticated("family:create", async (_req, res, context) => {
    noStore(res);
    res.status(201).json(service.createFamily(context.accountId, context.deviceId));
  }));

  app.post("/v1/family/invite", ...authenticated("family:invite", async (_req, res, context) => {
    noStore(res);
    res.status(201).json(service.createFamilyInvite(context.accountId));
  }));

  app.post("/v1/family/join", ...authenticated("family:join", async (req, res, context) => {
    const inviteCode = (req.body as { inviteCode?: unknown }).inviteCode;
    if (typeof inviteCode !== "string") throw new Error("Family invitation code is required.");
    noStore(res);
    res.json(service.joinFamily(context.accountId, context.deviceId, inviteCode));
  }));

  app.post("/v1/family/leave", ...authenticated("family:leave", async (_req, res, context) => {
    noStore(res);
    res.json(service.leaveFamily(context.accountId, context.deviceId));
  }));

  app.post("/v1/family/strict", ...authenticated("family:strict", async (req, res, context) => {
    const enabled = (req.body as { enabled?: unknown }).enabled;
    if (typeof enabled !== "boolean") throw new Error("Strict Family Protection requires a boolean enabled state.");
    noStore(res);
    res.json(service.setStrictFamilyProtection(context.accountId, context.deviceId, enabled));
  }));

  app.post("/v1/family/remove-member", ...authenticated("family:remove-member", async (req, res, context) => {
    const memberAccountId = (req.body as { memberAccountId?: unknown }).memberAccountId;
    if (typeof memberAccountId !== "string") throw new Error("Family member account ID is required.");
    noStore(res);
    res.json(service.removeFamilyMember(context.accountId, context.deviceId, memberAccountId));
  }));

  app.post("/v1/family/threat", ...authenticated("family:threat", async (req, res, context) => {
    const body = req.body as { campaignFingerprint?: unknown; source?: unknown };
    if (typeof body.campaignFingerprint !== "string" || (body.source !== "report_scam" && body.source !== "family_block")) {
      throw new Error("Family threat request requires a campaign fingerprint and explicit source.");
    }
    noStore(res);
    res.json({ familyThreats: service.recordFamilyThreat(context.accountId, body.campaignFingerprint, body.source) });
  }));

  app.put("/v1/internal/entitlements/:accountId", limited("entitlement-admin", 120, 60_000), (req, res) => {
    try {
      const token = req.get("authorization")?.replace(/^Bearer\s+/i, "") ?? "";
      if (!adminAuthorized(token, options.adminToken)) {
        noStore(res);
        return res.status(401).json({ error: "Account entitlement administration is not authorized." });
      }
      const entitlement = (req.body as { entitlement?: unknown }).entitlement as VerifiedEntitlement | undefined;
      if (!entitlement) throw new Error("Verified entitlement is required.");
      if (entitlement.source === "development" && options.allowDevelopmentEntitlements !== true) {
        throw new Error("Development entitlement source is not accepted by this account service.");
      }
      const snapshot = service.applyVerifiedEntitlement(req.params.accountId!, entitlement);
      noStore(res);
      res.json({ snapshot });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      noStore(res);
      res.status(errorStatus(message)).json({ error: message });
    }
  });

  app.use((_req, res) => {
    noStore(res);
    res.status(404).json({ error: "Unknown account service route." });
  });

  return app;
}
