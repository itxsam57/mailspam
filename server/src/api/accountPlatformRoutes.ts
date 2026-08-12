import type { Express, Request, Response } from "express";
import type { AccountPlatformService } from "../platform/accountFamilyService.js";
import type { DeviceIdentityPort } from "../platform/accountFamilyPorts.js";
import type { EmailShieldPlan, VerifiedEntitlement } from "../platform/accountFamilyTypes.js";

export interface AccountPlatformRouteDependencies {
  service: AccountPlatformService;
  deviceIdentity: DeviceIdentityPort & { currentDeviceId(): Promise<string> };
  resolveMailboxAccountKey(sessionId: string): string | null;
  developmentEntitlementsEnabled: boolean;
}

function noStore(res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

function errorResponse(res: Response, error: unknown, status = 400): void {
  noStore(res);
  res.status(status).json({ error: error instanceof Error ? error.message : String(error) });
}

function developmentEntitlement(plan: EmailShieldPlan, now: number): VerifiedEntitlement {
  return {
    plan,
    status: "active",
    source: "development",
    productId: `email-shield-${plan}-preview`,
    storeAccountReference: null,
    verifiedAt: now,
    expiresAt: null,
    graceUntil: null,
    seatLimit: plan === "family" ? 6 : 1,
  };
}

function validPlan(value: unknown): value is EmailShieldPlan {
  return value === "free" || value === "individual" || value === "family";
}

export function registerAccountPlatformRoutes(app: Express, dependencies: AccountPlatformRouteDependencies): void {
  const { service, deviceIdentity } = dependencies;

  app.get("/api/profile/v1/snapshot", async (_req: Request, res: Response) => {
    try {
      const deviceId = await deviceIdentity.currentDeviceId();
      noStore(res);
      res.json({
        schemaVersion: 1,
        persistent: service.persistent(),
        developmentEntitlementsEnabled: dependencies.developmentEntitlementsEnabled,
        ...service.snapshot(deviceId),
      });
    } catch (error) {
      errorResponse(res, error, 500);
    }
  });

  app.post("/api/profile/v1/accounts", async (req: Request, res: Response) => {
    try {
      const body = req.body as { username?: unknown; deviceLabel?: unknown };
      const baseIdentity = await deviceIdentity.currentPublicIdentity();
      const deviceLabel = typeof body.deviceLabel === "string" ? body.deviceLabel : "This desktop";
      const result = service.createAccount(body.username, { ...baseIdentity, label: deviceLabel });
      noStore(res);
      res.status(201).json({
        ...result,
        recoveryCodeNotice: "Store this recovery code somewhere safe. Email Shield stores only a one-way hash and cannot show this same code again.",
      });
    } catch (error) {
      errorResponse(res, error);
    }
  });

  app.post("/api/profile/v1/sign-in", async (req: Request, res: Response) => {
    try {
      const deviceId = await deviceIdentity.currentDeviceId();
      const snapshot = service.signIn((req.body as { username?: unknown }).username, deviceId);
      noStore(res);
      res.json(snapshot);
    } catch (error) {
      errorResponse(res, error, 401);
    }
  });

  app.post("/api/profile/v1/recover", async (req: Request, res: Response) => {
    try {
      const body = req.body as { username?: unknown; recoveryCode?: unknown; deviceLabel?: unknown };
      if (typeof body.recoveryCode !== "string") throw new Error("Recovery code is required.");
      const baseIdentity = await deviceIdentity.currentPublicIdentity();
      const deviceLabel = typeof body.deviceLabel === "string" ? body.deviceLabel : "Recovered desktop";
      const result = service.recoverAccount(body.username, body.recoveryCode, { ...baseIdentity, label: deviceLabel });
      noStore(res);
      res.json({
        ...result,
        recoveryCodeNotice: "Recovery succeeded. The old recovery code was rotated; store this replacement securely.",
      });
    } catch (error) {
      errorResponse(res, error, 401);
    }
  });

  app.post("/api/profile/v1/sign-out", async (_req: Request, res: Response) => {
    try {
      service.signOut();
      noStore(res);
      res.status(204).send();
    } catch (error) {
      errorResponse(res, error, 500);
    }
  });

  app.delete("/api/profile/v1/devices/:deviceId", async (req: Request, res: Response) => {
    try {
      const currentDeviceId = await deviceIdentity.currentDeviceId();
      const snapshot = service.revokeDevice(req.params.deviceId!, currentDeviceId);
      noStore(res);
      res.json(snapshot);
    } catch (error) {
      errorResponse(res, error);
    }
  });

  app.post("/api/profile/v1/entitlement/development", async (req: Request, res: Response) => {
    if (!dependencies.developmentEntitlementsEnabled) {
      return errorResponse(res, new Error("Development entitlement switching is disabled. Production plans must come from a verified store or web billing adapter."), 403);
    }
    try {
      const plan = (req.body as { plan?: unknown }).plan;
      if (!validPlan(plan)) throw new Error("Development plan must be free, individual or family.");
      const currentDeviceId = await deviceIdentity.currentDeviceId();
      const snapshot = service.applyVerifiedEntitlement(developmentEntitlement(plan, Date.now()), currentDeviceId);
      noStore(res);
      res.json({ previewOnly: true, source: "development", snapshot });
    } catch (error) {
      errorResponse(res, error);
    }
  });

  app.post("/api/profile/v1/family", async (_req: Request, res: Response) => {
    try {
      const currentDeviceId = await deviceIdentity.currentDeviceId();
      const snapshot = service.createFamily(currentDeviceId);
      noStore(res);
      res.status(201).json(snapshot);
    } catch (error) {
      errorResponse(res, error);
    }
  });

  app.post("/api/profile/v1/family/invites", async (_req: Request, res: Response) => {
    try {
      const invite = service.createFamilyInvite();
      noStore(res);
      res.status(201).json({
        ...invite,
        privacy: "Invitation contains no mailbox identity or email content. It is one-time and expires automatically.",
      });
    } catch (error) {
      errorResponse(res, error);
    }
  });

  app.post("/api/profile/v1/family/join", async (req: Request, res: Response) => {
    try {
      const inviteCode = (req.body as { inviteCode?: unknown }).inviteCode;
      if (typeof inviteCode !== "string") throw new Error("Family invitation code is required.");
      const currentDeviceId = await deviceIdentity.currentDeviceId();
      const snapshot = service.joinFamily(inviteCode, currentDeviceId);
      noStore(res);
      res.json(snapshot);
    } catch (error) {
      errorResponse(res, error);
    }
  });

  app.delete("/api/profile/v1/family/members/:accountId", async (req: Request, res: Response) => {
    try {
      const currentDeviceId = await deviceIdentity.currentDeviceId();
      const snapshot = service.removeFamilyMember(req.params.accountId!, currentDeviceId);
      noStore(res);
      res.json(snapshot);
    } catch (error) {
      errorResponse(res, error);
    }
  });

  app.post("/api/profile/v1/family/leave", async (_req: Request, res: Response) => {
    try {
      const currentDeviceId = await deviceIdentity.currentDeviceId();
      const snapshot = service.leaveFamily(currentDeviceId);
      noStore(res);
      res.json(snapshot);
    } catch (error) {
      errorResponse(res, error);
    }
  });

  app.post("/api/profile/v1/family/strict", async (req: Request, res: Response) => {
    try {
      const enabled = (req.body as { enabled?: unknown }).enabled;
      if (typeof enabled !== "boolean") throw new Error("Strict Family Protection requires a boolean enabled state.");
      const currentDeviceId = await deviceIdentity.currentDeviceId();
      const snapshot = service.setStrictFamilyProtection(enabled, currentDeviceId);
      noStore(res);
      res.json(snapshot);
    } catch (error) {
      errorResponse(res, error);
    }
  });

  app.post("/api/profile/v1/mailboxes/:sessionId/link", (req: Request, res: Response) => {
    try {
      const accountKey = dependencies.resolveMailboxAccountKey(req.params.sessionId!);
      if (!accountKey) return errorResponse(res, new Error("Connected mailbox session was not found."), 404);
      service.linkMailbox(accountKey);
      noStore(res);
      res.json({ linked: true, sessionId: req.params.sessionId });
    } catch (error) {
      errorResponse(res, error);
    }
  });
}
