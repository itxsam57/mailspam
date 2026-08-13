import { join } from "node:path";
import type { Express, Response } from "express";
import type { AccountPlatformService } from "../platform/accountFamilyService.js";
import type { DeviceIdentityPort } from "../platform/accountFamilyPorts.js";
import { defaultEmailShieldDataDirectory } from "../security/dataDirectory.js";
import {
  FileFamilyGuardianPreferencesRepository,
  normalizeFamilyGuardianPreferences,
  type FamilyGuardianPreferencesRepository,
} from "../consumer/familyGuardianPreferences.js";

export interface FamilyGuardianPreferenceRouteDependencies {
  accountPlatform: AccountPlatformService;
  deviceIdentity: DeviceIdentityPort & { currentDeviceId(): Promise<string> };
  repository?: FamilyGuardianPreferencesRepository;
}

function noStore(res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

function fail(res: Response, error: unknown, status = 400): void {
  noStore(res);
  res.status(status).json({ error: error instanceof Error ? error.message : String(error) });
}

export function registerFamilyGuardianPreferenceRoutes(
  app: Express,
  dependencies: FamilyGuardianPreferenceRouteDependencies,
): void {
  const repository = dependencies.repository ?? new FileFamilyGuardianPreferencesRepository(
    join(defaultEmailShieldDataDirectory(), "family-guardian-preferences.json"),
  );

  async function currentFamilyAccount() {
    const deviceId = await dependencies.deviceIdentity.currentDeviceId();
    const snapshot = dependencies.accountPlatform.snapshot(deviceId);
    if (!snapshot.signedIn || !snapshot.account) throw new Error("Sign in to your Email Shield account first.");
    return snapshot;
  }

  app.get("/api/consumer/v1/family/preferences", async (_req, res) => {
    try {
      const snapshot = await currentFamilyAccount();
      noStore(res);
      res.json({
        available: Boolean(snapshot.family),
        preferences: repository.load(snapshot.account!.accountId),
        privacy: "hashed_account_key_preferences_only",
      });
    } catch (error) { fail(res, error, 401); }
  });

  app.post("/api/consumer/v1/family/preferences", async (req, res) => {
    try {
      const snapshot = await currentFamilyAccount();
      if (!snapshot.family) throw new Error("Family Guardian preferences require an active Family Shield circle.");
      const normalized = normalizeFamilyGuardianPreferences(req.body);
      const saved = repository.save(snapshot.account!.accountId, normalized);
      noStore(res);
      res.json({
        saved: true,
        preferences: saved,
        privacy: "hashed_account_key_preferences_only",
      });
    } catch (error) { fail(res, error); }
  });
}
