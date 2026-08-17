import type { Express, Request, Response } from "express";
import { Worker } from "node:worker_threads";
import type { AccountPlatformService } from "../platform/accountFamilyService.js";
import type { DeviceIdentityPort } from "../platform/accountFamilyPorts.js";
import { sessionStore, type SessionStore } from "./sessionStore.js";
import { defaultConsumerStateRepository } from "./defaultConsumerStateRepository.js";
import { defaultRelationshipHistoryRepository } from "./defaultRelationshipHistoryRepository.js";
import { createAdapter } from "./adapterConfig.js";
import { localOperationalMetrics } from "./localOperationalMetrics.js";
import { resolveRuntimeReleaseIdentity } from "./runtimeReleaseIdentity.js";
import { destinationAnalysisCoordinator, type DestinationAnalysisCoordinator } from "../workflows/analyzeLinks.js";
import { evaluateBrowserUrl } from "../consumer/browserProtection.js";
import { analyzeMobileScamInput } from "../consumer/mobileProtection.js";
import { assessScamIntervention } from "../consumer/intervention.js";
import {
  campaignRadar,
  createTrustedAssistancePacket,
  familyActivitySummary,
} from "../consumer/familyGuardian.js";
import {
  checkEmailExposure,
  checkPasswordExposure,
  HttpExposureLookupPort,
  UnconfiguredExposureLookupPort,
  type ExposureLookupPort,
} from "../consumer/identityExposure.js";
import {
  normalizeProtectionSensitivityProfile,
} from "../consumer/protectionSensitivity.js";
import type { CommunityNetwork } from "../community/network.js";
import { communityNetwork } from "../community/network.js";
import type { ConsumerRuleType } from "./consumerStatePersistence.js";
import type { Provider } from "../canonical/envelope.js";

const HEALTH_TIMEOUT_MS = 190_000;
const UNDO_TIMEOUT_MS = 45_000;
const UNDO_WINDOW_MS = 30 * 60 * 1_000;

interface HealthInspectResult {
  inboxHealth: Record<string, unknown>;
  mailboxHealth: Record<string, unknown>;
  digitalFootprint: Record<string, unknown>;
}

interface CleanupWorkerResult {
  matched: number;
  movedToTrash: number;
  keptNewest: boolean;
  bounded: boolean;
  providerNativeIds: string[];
  fixtureFolderOverrides?: Record<string, "inbox" | "spam" | "trash">;
}

export interface ConsumerProtectionRouteDependencies {
  sessions?: SessionStore;
  accountPlatform?: AccountPlatformService;
  deviceIdentity?: DeviceIdentityPort & { currentDeviceId(): Promise<string> };
  community?: CommunityNetwork;
  destinationAnalyzer?: DestinationAnalysisCoordinator;
  exposureLookup?: ExposureLookupPort;
}

function noStore(res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

function errorResponse(res: Response, error: unknown, status = 400): void {
  noStore(res);
  res.status(status).json({ error: error instanceof Error ? error.message : String(error) });
}

function requireSession(sessions: SessionStore, req: Request, res: Response) {
  const session = sessions.get(req.params.id!);
  if (!session) {
    errorResponse(res, new Error("Unknown connected mailbox."), 404);
    return null;
  }
  return session;
}

function restoreSupported(provider: Provider, fixture: boolean): boolean {
  return fixture || provider === "gmail" || provider === "outlook";
}

function runHealthWorker(
  session: NonNullable<ReturnType<SessionStore["get"]>>,
  mode: "inspect" | "cleanup",
  cleanup?: { senderAddress?: string; senderDomain?: string; olderThanDays?: number; keepNewest?: boolean },
): Promise<HealthInspectResult | CleanupWorkerResult> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("../workers/consumerHealthWorker.js", import.meta.url), {
      workerData: {
        config: session.config,
        provider: session.config.provider,
        mode,
        cleanup,
        relationshipHistory: defaultRelationshipHistoryRepository.workerSnapshot(session.policyAccountKey),
      },
    });
    let settled = false;
    const finish = (error: Error | null, result?: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      void worker.terminate().catch(() => undefined);
      if (error) reject(error);
      else resolve(result as HealthInspectResult | CleanupWorkerResult);
    };
    const timer = setTimeout(() => {
      worker.postMessage({ type: "cancel" });
      finish(new Error("Consumer mailbox health operation exceeded its bounded deadline."));
    }, HEALTH_TIMEOUT_MS);
    worker.on("message", (message: any) => {
      if (message?.type === "result") finish(null, message.result);
      else if (message?.type === "error") finish(new Error(String(message.error || "Consumer mailbox health worker failed.")));
    });
    worker.once("error", (error) => finish(error));
    worker.once("exit", (code) => {
      if (!settled) finish(new Error(`Consumer mailbox health worker exited before returning a result (${code}).`));
    });
  });
}

function normalizedSelector(body: Record<string, unknown>): { senderAddress: string | null; senderDomain: string | null } {
  const senderAddress = typeof body.senderAddress === "string" ? body.senderAddress.trim().toLowerCase() : null;
  const senderDomain = typeof body.senderDomain === "string" ? body.senderDomain.trim().toLowerCase().replace(/^@/, "") : null;
  if (senderAddress && (senderAddress.length > 320 || !senderAddress.includes("@"))) throw new Error("Rule sender address is invalid.");
  if (senderDomain && (senderDomain.length > 253 || !/^[a-z0-9.-]+$/.test(senderDomain))) throw new Error("Rule sender domain is invalid.");
  return { senderAddress, senderDomain };
}

function exposurePortFromEnvironment(): ExposureLookupPort {
  const url = process.env.EMAIL_SHIELD_EXPOSURE_SERVICE_URL?.trim();
  return url ? new HttpExposureLookupPort(url) : new UnconfiguredExposureLookupPort();
}

function publicState(accountKey: string) {
  const state = defaultConsumerStateRepository.snapshot(accountKey);
  return {
    persistent: defaultConsumerStateRepository.persistent,
    sensitivity: state.sensitivity,
    rules: state.rules,
    richerLocalNotifications: state.richerLocalNotifications,
    onboarding: state.onboarding,
    activity: defaultConsumerStateRepository.listActivity(accountKey),
  };
}

export function registerConsumerProtectionRoutes(
  app: Express,
  dependencies: ConsumerProtectionRouteDependencies = {},
): void {
  const sessions = dependencies.sessions ?? sessionStore;
  const community = dependencies.community ?? communityNetwork;
  const destinationAnalyzer = dependencies.destinationAnalyzer ?? destinationAnalysisCoordinator;
  const exposureLookup = dependencies.exposureLookup ?? exposurePortFromEnvironment();

  app.get("/api/consumer/v1/accounts/:id/state", (req, res) => {
    const session = requireSession(sessions, req, res);
    if (!session) return;
    try {
      noStore(res);
      res.json(publicState(session.policyAccountKey));
    } catch (error) { errorResponse(res, error, 500); }
  });

  app.post("/api/consumer/v1/accounts/:id/sensitivity", (req, res) => {
    const session = requireSession(sessions, req, res);
    if (!session) return;
    try {
      const profile = normalizeProtectionSensitivityProfile((req.body as { profile?: unknown }).profile);
      defaultConsumerStateRepository.setSensitivity(session.policyAccountKey, profile);
      defaultConsumerStateRepository.appendActivity(session.policyAccountKey, {
        kind: "settings",
        severity: "info",
        provider: session.config.provider,
        title: "Protection profile changed",
        detail: `Protection attention profile changed to ${profile.replace(/_/g, " ")}. Hard security signals remain locked and cannot be suppressed.`,
        reasonCodes: ["SENSITIVITY_CHANGED"],
        undo: null,
      });
      noStore(res);
      res.json(publicState(session.policyAccountKey));
    } catch (error) { errorResponse(res, error); }
  });

  app.post("/api/consumer/v1/accounts/:id/notifications", (req, res) => {
    const session = requireSession(sessions, req, res);
    if (!session) return;
    const enabled = (req.body as { richerLocalNotifications?: unknown }).richerLocalNotifications;
    if (typeof enabled !== "boolean") return errorResponse(res, new Error("Notification privacy preference must be boolean."));
    try {
      defaultConsumerStateRepository.setRicherLocalNotifications(session.policyAccountKey, enabled);
      noStore(res);
      res.json(publicState(session.policyAccountKey));
    } catch (error) { errorResponse(res, error); }
  });

  app.post("/api/consumer/v1/accounts/:id/onboarding", (req, res) => {
    const session = requireSession(sessions, req, res);
    if (!session) return;
    const body = req.body as { completedSteps?: unknown; dismissed?: unknown };
    if (!Array.isArray(body.completedSteps)) return errorResponse(res, new Error("Onboarding completedSteps must be an array."));
    try {
      const completedSteps = body.completedSteps.filter((item): item is string => typeof item === "string").slice(0, 30);
      defaultConsumerStateRepository.setOnboarding(session.policyAccountKey, {
        completedSteps,
        dismissedAt: body.dismissed === true ? Date.now() : null,
      });
      noStore(res);
      res.json(publicState(session.policyAccountKey));
    } catch (error) { errorResponse(res, error); }
  });

  app.post("/api/consumer/v1/accounts/:id/rules", (req, res) => {
    const session = requireSession(sessions, req, res);
    if (!session) return;
    try {
      const body = req.body as Record<string, unknown>;
      const type = body.type as ConsumerRuleType;
      if (!(["mute_notifications", "read_later", "screen_first_contact"] as const).includes(type as "mute_notifications" | "read_later" | "screen_first_contact")) {
        throw new Error("Consumer attention rule type is invalid. Catch & Trash is managed through its dedicated encrypted personal-policy endpoint.");
      }
      const selector = normalizedSelector(body);
      if (type !== "screen_first_contact" && !selector.senderAddress && !selector.senderDomain) throw new Error("This rule requires a sender address or domain.");
      const expiresAt = body.expiresAt === null || body.expiresAt === undefined
        ? null
        : Number(body.expiresAt);
      if (expiresAt !== null && (!Number.isSafeInteger(expiresAt) || expiresAt <= Date.now())) throw new Error("Rule expiry is invalid.");
      const rule = defaultConsumerStateRepository.upsertRule(session.policyAccountKey, {
        type,
        enabled: body.enabled !== false,
        senderAddress: selector.senderAddress,
        senderDomain: selector.senderDomain,
        expiresAt,
      });
      defaultConsumerStateRepository.appendActivity(session.policyAccountKey, {
        kind: "settings",
        severity: "info",
        provider: session.config.provider,
        title: "Local mailbox attention rule saved",
        detail: `Local ${type.replace(/_/g, " ")} preference saved. It does not weaken hard threat detection or create a destructive mailbox action.`,
        reasonCodes: [`RULE_${type.toUpperCase()}`],
        undo: null,
      });
      noStore(res);
      res.status(201).json({ rule, state: publicState(session.policyAccountKey) });
    } catch (error) { errorResponse(res, error); }
  });

  app.delete("/api/consumer/v1/accounts/:id/rules/:ruleId", (req, res) => {
    const session = requireSession(sessions, req, res);
    if (!session) return;
    try {
      const removed = defaultConsumerStateRepository.removeRule(session.policyAccountKey, req.params.ruleId ?? "");
      noStore(res);
      res.status(removed ? 200 : 404).json({ removed, state: publicState(session.policyAccountKey) });
    } catch (error) { errorResponse(res, error); }
  });

  app.post("/api/consumer/v1/accounts/:id/health", async (req, res) => {
    const session = requireSession(sessions, req, res);
    if (!session) return;
    try {
      const result = await runHealthWorker(session, "inspect") as HealthInspectResult;
      defaultConsumerStateRepository.appendActivity(session.policyAccountKey, {
        kind: "health_check",
        severity: (result.mailboxHealth as any)?.state === "critical" ? "critical" : (result.mailboxHealth as any)?.state === "attention" ? "warning" : "info",
        provider: session.config.provider,
        title: "Inbox & Mailbox Health checked",
        detail: "Email Shield completed a bounded local mailbox inventory and compromise-indicator check. Unsupported provider settings remain explicitly unavailable, not safe.",
        reasonCodes: ["CONSUMER_HEALTH_CHECK"],
        undo: null,
      });
      noStore(res);
      res.json(result);
    } catch (error) { errorResponse(res, error, 502); }
  });

  app.post("/api/consumer/v1/accounts/:id/cleanup", async (req, res) => {
    const session = requireSession(sessions, req, res);
    if (!session) return;
    try {
      const body = req.body as Record<string, unknown>;
      if (body.confirmation !== "MOVE TO TRASH") throw new Error("Type MOVE TO TRASH to confirm bulk cleanup.");
      const selector = normalizedSelector(body);
      if (!selector.senderAddress && !selector.senderDomain) throw new Error("Choose an exact sender or domain from Inbox Health before cleanup.");
      const olderThanDays = body.olderThanDays === undefined ? undefined : Number(body.olderThanDays);
      const keepNewest = body.keepNewest === true;
      const result = await runHealthWorker(session, "cleanup", {
        senderAddress: selector.senderAddress ?? undefined,
        senderDomain: selector.senderDomain ?? undefined,
        olderThanDays,
        keepNewest,
      }) as CleanupWorkerResult;
      if (session.config.mode === "fixture" && result.fixtureFolderOverrides) {
        session.config.fixtureFolderOverrides = {
          ...(session.config.fixtureFolderOverrides ?? {}),
          ...result.fixtureFolderOverrides,
        };
      }
      const provider = session.config.provider;
      const changed = result.movedToTrash > 0;
      const canUndo = changed && result.providerNativeIds.length > 0 && restoreSupported(provider, session.config.mode === "fixture");
      const activity = defaultConsumerStateRepository.appendActivity(session.policyAccountKey, {
        kind: "cleanup",
        severity: "info",
        provider,
        title: changed ? "Mailbox cleanup completed" : "Mailbox cleanup made no changes",
        detail: changed
          ? `${result.movedToTrash} matching message(s) were moved to Trash after explicit confirmation.${result.bounded ? " The operation was bounded; additional matching mail may remain." : ""}`
          : `No matching messages remained eligible for the requested cleanup.${result.bounded ? " The bounded Health inventory may not include every mailbox message." : ""}`,
        reasonCodes: [changed ? "BULK_CLEANUP_TO_TRASH" : "BULK_CLEANUP_NO_CHANGE"],
        undo: canUndo ? {
          providerNativeIds: result.providerNativeIds,
          expiresAt: Date.now() + UNDO_WINDOW_MS,
          usedAt: null,
        } : null,
      });
      noStore(res);
      res.json({
        matched: result.matched,
        movedToTrash: result.movedToTrash,
        keptNewest: result.keptNewest,
        bounded: result.bounded,
        activityId: activity.activityId,
        undoAvailable: canUndo,
        undoExpiresAt: canUndo ? activity.undo!.expiresAt : null,
      });
    } catch (error) { errorResponse(res, error, 502); }
  });

  app.post("/api/consumer/v1/accounts/:id/activity/:activityId/undo", async (req, res) => {
    const session = requireSession(sessions, req, res);
    if (!session) return;
    const activity = defaultConsumerStateRepository.getActivity(session.policyAccountKey, req.params.activityId ?? "");
    if (!activity?.undo) return errorResponse(res, new Error("This activity has no provider-safe Undo."), 409);
    if (activity.undo.usedAt !== null) return errorResponse(res, new Error("This activity was already undone."), 409);
    if (activity.undo.expiresAt <= Date.now()) return errorResponse(res, new Error("The provider-safe Undo window has expired."), 409);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), UNDO_TIMEOUT_MS);
    const adapter = createAdapter(session.config);
    try {
      await adapter.connect(controller.signal);
      const result = adapter.restoreToInbox
        ? await adapter.restoreToInbox(activity.undo.providerNativeIds, controller.signal)
        : { requested: activity.undo.providerNativeIds.length, restored: 0, supported: false, mode: "unsupported" as const };
      if (!result.supported || result.restored !== activity.undo.providerNativeIds.length) {
        throw new Error(result.reason ?? "The provider did not safely restore every protected message.");
      }
      defaultConsumerStateRepository.markActivityUndone(session.policyAccountKey, activity.activityId);
      defaultConsumerStateRepository.appendActivity(session.policyAccountKey, {
        kind: "restored",
        severity: "info",
        provider: session.config.provider,
        title: "Protection action undone",
        detail: `${result.restored} message(s) were restored to Inbox using the provider's stable message identity.`,
        reasonCodes: ["PROVIDER_RESTORE_TO_INBOX"],
        undo: null,
      });
      noStore(res);
      res.json({ restored: result.restored, activity: defaultConsumerStateRepository.listActivity(session.policyAccountKey) });
    } catch (error) { errorResponse(res, error, 502); }
    finally {
      clearTimeout(timer);
      await adapter.disconnect().catch(() => undefined);
    }
  });

  app.get("/api/consumer/v1/accounts/:id/activity", (req, res) => {
    const session = requireSession(sessions, req, res);
    if (!session) return;
    noStore(res);
    res.json({ activity: defaultConsumerStateRepository.listActivity(session.policyAccountKey) });
  });

  app.delete("/api/consumer/v1/accounts/:id/activity", (req, res) => {
    const session = requireSession(sessions, req, res);
    if (!session) return;
    try {
      if ((req.body as { confirmation?: unknown }).confirmation !== "CLEAR ACTIVITY") throw new Error("Type CLEAR ACTIVITY to confirm local activity deletion.");
      defaultConsumerStateRepository.clearActivity(session.policyAccountKey);
      noStore(res);
      res.json({ cleared: true });
    } catch (error) { errorResponse(res, error); }
  });

  app.post("/api/consumer/v1/browser/check", async (req, res) => {
    try {
      const result = await evaluateBrowserUrl(req.body, {
        destinationAnalyzer,
        scamCheck: { intelligenceEntries: community.getVerifiedEntries() },
      });
      noStore(res);
      res.json(result);
    } catch (error) { errorResponse(res, error); }
  });

  app.post("/api/consumer/v1/mobile/check", (req, res) => {
    try {
      const result = analyzeMobileScamInput(req.body);
      noStore(res);
      res.json(result);
    } catch (error) { errorResponse(res, error); }
  });

  app.post("/api/consumer/v1/intervention/check", (req, res) => {
    try {
      const text = (req.body as { text?: unknown }).text;
      if (typeof text !== "string" || text.length < 1 || text.length > 32_000) throw new Error("Intervention analysis requires bounded text.");
      noStore(res);
      res.json(assessScamIntervention(text));
    } catch (error) { errorResponse(res, error); }
  });

  app.get("/api/consumer/v1/family/summary", async (_req, res) => {
    if (!dependencies.accountPlatform || !dependencies.deviceIdentity) return errorResponse(res, new Error("Family Shield account platform is unavailable."), 503);
    try {
      const deviceId = await dependencies.deviceIdentity.currentDeviceId();
      noStore(res);
      res.json(familyActivitySummary(dependencies.accountPlatform.snapshot(deviceId)));
    } catch (error) { errorResponse(res, error); }
  });

  app.get("/api/consumer/v1/radar", (_req, res) => {
    try {
      noStore(res);
      res.json(campaignRadar(community.getVerifiedEntries()));
    } catch (error) { errorResponse(res, error, 503); }
  });

  app.post("/api/consumer/v1/family/assistance", (req, res) => {
    try {
      const body = req.body as Record<string, unknown>;
      const verdict = body.verdict;
      if (verdict !== "review" && verdict !== "high_risk" && verdict !== "confirmed_threat" && verdict !== "unknown") throw new Error("Assistance packet verdict is invalid.");
      if (typeof body.textForCategory !== "string" || body.textForCategory.length > 24_000) throw new Error("Assistance packet category text is invalid.");
      const strongestSignals = Array.isArray(body.strongestSignals) ? body.strongestSignals.filter((item): item is string => typeof item === "string") : [];
      const packet = createTrustedAssistancePacket({
        verdict,
        textForCategory: body.textForCategory,
        strongestSignals,
        safeNextAction: typeof body.safeNextAction === "string" ? body.safeNextAction : "Verify independently before acting.",
        userNote: typeof body.userNote === "string" ? body.userNote : null,
        excerpt: typeof body.excerpt === "string" ? body.excerpt : null,
        shareExcerpt: body.shareExcerpt === true,
      });
      noStore(res);
      res.json(packet);
    } catch (error) { errorResponse(res, error); }
  });

  app.post("/api/consumer/v1/exposure/email", async (req, res) => {
    try {
      const email = (req.body as { email?: unknown; consent?: unknown }).email;
      const consent = (req.body as { consent?: unknown }).consent;
      if (consent !== true) throw new Error("Email exposure lookup requires explicit user consent.");
      if (typeof email !== "string") throw new Error("Email address is required.");
      const result = await checkEmailExposure(email, exposureLookup);
      noStore(res);
      res.json(result);
    } catch (error) { errorResponse(res, error); }
  });

  app.post("/api/consumer/v1/exposure/password", async (req, res) => {
    try {
      const password = (req.body as { password?: unknown; consent?: unknown }).password;
      const consent = (req.body as { consent?: unknown }).consent;
      if (consent !== true) throw new Error("Credential exposure lookup requires explicit user consent.");
      if (typeof password !== "string") throw new Error("Credential value is required.");
      const result = await checkPasswordExposure(password, exposureLookup);
      noStore(res);
      res.json(result);
    } catch (error) { errorResponse(res, error); }
  });

  app.get("/api/consumer/v1/support-bundle", (_req, res) => {
    try {
      const connected = sessions.list().map((session) => ({
        provider: session.config.provider,
        mode: session.config.mode,
        credentialStorage: session.config.mode === "live" ? "native_vault_reference" : "fixture",
      }));
      const activityCounts = sessions.list().reduce<Record<string, number>>((counts, session) => {
        for (const item of defaultConsumerStateRepository.listActivity(session.policyAccountKey)) counts[item.kind] = (counts[item.kind] ?? 0) + 1;
        return counts;
      }, {});
      const releaseIdentity = resolveRuntimeReleaseIdentity();
      noStore(res);
      res.json({
        schemaVersion: 1,
        generatedAt: new Date().toISOString(),
        app: { version: releaseIdentity.version, release: releaseIdentity.release },
        runtime: { node: process.version, platform: process.platform, arch: process.arch },
        connected,
        activityCounts,
        operational: localOperationalMetrics.snapshot(),
        privacy: "no_credentials_tokens_mail_content_subject_sender_url_family_private_data_or_device_keys",
      });
    } catch (error) { errorResponse(res, error, 500); }
  });
}
