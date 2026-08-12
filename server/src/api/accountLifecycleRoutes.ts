import express, { type Express, type NextFunction, type Request, type Response } from "express";
import type { AccountLifecycleService } from "../platform/accountLifecycleService.js";
import type { DeviceIdentityPort } from "../platform/accountFamilyPorts.js";
import type { LocalSecurityManager } from "./localSecurity.js";

export interface AccountLifecycleRouteDependencies {
  lifecycle: AccountLifecycleService;
  deviceIdentity: DeviceIdentityPort & { currentDeviceId(): Promise<string> };
  security: LocalSecurityManager;
}

function noStore(res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

function errorResponse(res: Response, error: unknown, status = 400): void {
  noStore(res);
  res.status(status).json({ error: error instanceof Error ? error.message : String(error) });
}

function exactConfirmation(body: unknown, expected: string): void {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error(`Type ${expected} to confirm this action.`);
  const value = body as Record<string, unknown>;
  if (Object.keys(value).some((key) => key !== "confirmation") || value.confirmation !== expected) {
    throw new Error(`Type ${expected} to confirm this action.`);
  }
}

function protectedRead(dependencies: AccountLifecycleRouteDependencies) {
  return [
    dependencies.security.validateLoopbackRequest,
    dependencies.security.securityHeaders,
    dependencies.security.requireProtectedRead(),
    dependencies.security.requireSameOrigin(),
  ];
}

function protectedMutation(dependencies: AccountLifecycleRouteDependencies) {
  return [
    dependencies.security.validateLoopbackRequest,
    dependencies.security.securityHeaders,
    dependencies.security.requireMutation(),
  ];
}

function routeLimit(dependencies: AccountLifecycleRouteDependencies, key: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!dependencies.security.enforceRouteLimit(req, res, key, 20)) return;
    next();
  };
}

export function registerAccountLifecycleRoutes(app: Express, dependencies: AccountLifecycleRouteDependencies): void {
  const { lifecycle, deviceIdentity } = dependencies;

  app.get(
    "/api/profile/v1/export",
    ...protectedRead(dependencies),
    routeLimit(dependencies, "account-lifecycle-export"),
    async (_req: Request, res: Response) => {
      try {
        const currentDeviceId = await deviceIdentity.currentDeviceId();
        noStore(res);
        res.json(lifecycle.exportAccountMetadata(currentDeviceId));
      } catch (error) {
        errorResponse(res, error);
      }
    },
  );

  app.post(
    "/api/profile/v1/recovery/rotate",
    ...protectedMutation(dependencies),
    routeLimit(dependencies, "account-lifecycle-recovery"),
    async (_req: Request, res: Response) => {
      try {
        const currentDeviceId = await deviceIdentity.currentDeviceId();
        const result = lifecycle.rotateRecoveryCode(currentDeviceId);
        noStore(res);
        res.json({
          ...result,
          recoveryCodeNotice: "The previous recovery code is invalid now. Store this replacement securely; Email Shield keeps only its one-way hash.",
        });
      } catch (error) {
        errorResponse(res, error);
      }
    },
  );

  app.post(
    "/api/profile/v1/devices/revoke-others",
    ...protectedMutation(dependencies),
    routeLimit(dependencies, "account-lifecycle-devices"),
    async (_req: Request, res: Response) => {
      try {
        const currentDeviceId = await deviceIdentity.currentDeviceId();
        noStore(res);
        res.json(lifecycle.revokeOtherDevices(currentDeviceId));
      } catch (error) {
        errorResponse(res, error);
      }
    },
  );

  app.post(
    "/api/profile/v1/sign-out-everywhere",
    ...protectedMutation(dependencies),
    routeLimit(dependencies, "account-lifecycle-signout"),
    async (_req: Request, res: Response) => {
      try {
        const currentDeviceId = await deviceIdentity.currentDeviceId();
        noStore(res);
        res.json({
          ...lifecycle.signOutEverywhere(currentDeviceId),
          signedOut: true,
          recoveryRequired: true,
        });
      } catch (error) {
        errorResponse(res, error);
      }
    },
  );

  app.delete(
    "/api/profile/v1/family",
    ...protectedMutation(dependencies),
    routeLimit(dependencies, "account-lifecycle-delete-family"),
    express.json({ limit: "2kb", strict: true }),
    async (req: Request, res: Response) => {
      try {
        exactConfirmation(req.body, "DELETE FAMILY");
        const currentDeviceId = await deviceIdentity.currentDeviceId();
        noStore(res);
        res.json(lifecycle.deleteFamilyCircle(currentDeviceId));
      } catch (error) {
        errorResponse(res, error);
      }
    },
  );

  app.delete(
    "/api/profile/v1/account",
    ...protectedMutation(dependencies),
    routeLimit(dependencies, "account-lifecycle-delete-account"),
    express.json({ limit: "2kb", strict: true }),
    async (req: Request, res: Response) => {
      try {
        exactConfirmation(req.body, "DELETE ACCOUNT");
        const currentDeviceId = await deviceIdentity.currentDeviceId();
        const result = lifecycle.deleteAccount(currentDeviceId);
        noStore(res);
        res.json({
          ...result,
          mailboxContentDeleted: false,
          localMailboxConnectionsDeleted: false,
          notice: "The Email Shield profile was deleted. Local mailbox connections and mailbox contents are separate and were not deleted by this profile action.",
        });
      } catch (error) {
        errorResponse(res, error);
      }
    },
  );
}
