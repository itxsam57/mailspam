import express from "express";
import type { NextFunction, Request, Response } from "express";
import type { SharedAccountFamilyService } from "./service.js";
import { SharedAccountLifecycleService } from "./lifecycleService.js";
import type { AccountServiceAuthProof, AccountServiceOperation } from "./types.js";
import type { AccountServiceStore } from "./store.js";

const LIFECYCLE_OPERATIONS = new Set<AccountServiceOperation>([
  "account:export",
  "account:delete",
  "recovery:rotate",
  "devices:revoke-others",
  "devices:signout-everywhere",
  "family:delete",
]);

const FORBIDDEN_FIELDS = new Set([
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
  "mailboxaccountkey",
  "rawurl",
  "attachmentbody",
  "apppassword",
  "accesstoken",
  "refreshtoken",
  "oauthcode",
]);

interface RateState { startedAt: number; count: number; }

function noStore(res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

function headers(_req: Request, res: Response, next: NextFunction): void {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
  next();
}

function inspect(value: unknown, depth = 0): void {
  if (depth > 6) throw new Error("Account lifecycle request nesting is too deep.");
  if (Array.isArray(value)) {
    if (value.length > 32) throw new Error("Account lifecycle request array is too large.");
    for (const item of value) inspect(item, depth + 1);
    return;
  }
  if (!value || typeof value !== "object") return;
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length > 24) throw new Error("Account lifecycle request contains too many fields.");
  for (const [key, child] of Object.entries(record)) {
    if (FORBIDDEN_FIELDS.has(key.toLowerCase())) throw new Error(`Account lifecycle rejects mailbox/provider-secret field ${key}.`);
    inspect(child, depth + 1);
  }
}

function authProof(body: unknown): AccountServiceAuthProof {
  const value = (body as { auth?: unknown })?.auth;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Device authentication proof is required.");
  const record = value as Record<string, unknown>;
  if (Object.keys(record).some((key) => key !== "challengeId" && key !== "signature")
    || typeof record.challengeId !== "string"
    || typeof record.signature !== "string") {
    throw new Error("Device authentication proof is invalid.");
  }
  return { challengeId: record.challengeId, signature: record.signature };
}

function accountId(body: unknown): string {
  const value = (body as { accountId?: unknown })?.accountId;
  if (typeof value !== "string") throw new Error("Email Shield account ID is required.");
  return value;
}

function confirmation(body: unknown, expected: string): void {
  if ((body as { confirmation?: unknown })?.confirmation !== expected) throw new Error(`Type ${expected} to confirm this destructive action.`);
}

function statusFor(message: string): number {
  if (/signature|authentication|not registered|trusted device|unknown account/i.test(message)) return 401;
  if (/owner|family|already|must|confirm/i.test(message)) return 409;
  return 400;
}

export function createAccountLifecycleServer(
  accountService: SharedAccountFamilyService,
  store: AccountServiceStore,
  options: { trustProxy?: boolean; now?: () => number } = {},
) {
  const app = express();
  app.disable("x-powered-by");
  if (options.trustProxy) app.set("trust proxy", 1);
  app.use(headers);
  app.use(express.json({ limit: "12kb", strict: true }));
  const lifecycle = new SharedAccountLifecycleService(store, options.now);
  const rate = new Map<string, RateState>();

  const limited = (bucket: string, max: number, windowMs: number) => (req: Request, res: Response, next: NextFunction) => {
    const now = Date.now();
    const key = `${bucket}:${req.ip || req.socket.remoteAddress || "unknown"}`;
    const old = rate.get(key);
    const state = !old || now - old.startedAt >= windowMs ? { startedAt: now, count: 0 } : old;
    state.count += 1;
    rate.set(key, state);
    if (state.count > max) {
      noStore(res);
      res.status(429).json({ error: "Account lifecycle rate limit exceeded." });
      return;
    }
    next();
  };

  app.use((req, res, next) => {
    try {
      if (req.body !== undefined) inspect(req.body);
      next();
    } catch (error) {
      noStore(res);
      res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.post("/v1/lifecycle/auth/challenge", limited("challenge", 30, 60_000), (req, res) => {
    try {
      const body = req.body as { accountId?: unknown; deviceId?: unknown; operation?: unknown };
      if (typeof body.operation !== "string" || !LIFECYCLE_OPERATIONS.has(body.operation as AccountServiceOperation)) {
        throw new Error("Account lifecycle operation is invalid.");
      }
      const challenge = accountService.issueChallenge(body.accountId, body.deviceId, body.operation as AccountServiceOperation);
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
      res.status(statusFor(message)).json({ error: message });
    }
  });

  const authenticated = (
    operation: AccountServiceOperation,
    handler: (req: Request, res: Response, context: { accountId: string; deviceId: string }) => unknown,
  ) => [limited("authenticated", 90, 60_000), (req: Request, res: Response) => {
    try {
      const id = accountId(req.body);
      const authenticatedDevice = accountService.authenticate(id, operation, authProof(req.body));
      const result = handler(req, res, { accountId: id, deviceId: authenticatedDevice.device.deviceId });
      noStore(res);
      if (!res.headersSent) res.json(result);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      noStore(res);
      res.status(statusFor(message)).json({ error: message });
    }
  }] as const;

  app.post("/v1/lifecycle/account/export", ...authenticated("account:export", (_req, _res, context) =>
    lifecycle.exportAccount(context.accountId, context.deviceId)));

  app.post("/v1/lifecycle/recovery/rotate", ...authenticated("recovery:rotate", (_req, _res, context) => ({
    ...lifecycle.rotateRecovery(context.accountId, context.deviceId),
    recoveryCodeNotice: "The previous recovery code is invalid. Store this replacement securely.",
  })));

  app.post("/v1/lifecycle/devices/revoke-others", ...authenticated("devices:revoke-others", (_req, _res, context) =>
    lifecycle.revokeOtherDevices(context.accountId, context.deviceId)));

  app.post("/v1/lifecycle/signout-everywhere", ...authenticated("devices:signout-everywhere", (_req, _res, context) => ({
    ...lifecycle.signOutEverywhere(context.accountId, context.deviceId),
    recoveryRequired: true,
  })));

  app.post("/v1/lifecycle/family/delete", ...authenticated("family:delete", (req, _res, context) => {
    confirmation(req.body, "DELETE FAMILY");
    return lifecycle.deleteFamily(context.accountId, context.deviceId);
  }));

  app.post("/v1/lifecycle/account/delete", ...authenticated("account:delete", (req, _res, context) => {
    confirmation(req.body, "DELETE ACCOUNT");
    return {
      ...lifecycle.deleteAccount(context.accountId, context.deviceId),
      mailboxContentDeleted: false,
      mailboxIdentityStoredByService: false,
    };
  }));

  return app;
}
