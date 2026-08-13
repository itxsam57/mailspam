import type { Express, Request, Response } from "express";
import type { EmailAdapter } from "../canonical/adapter.js";
import type { SecureAdapterConfig } from "../security/secureAdapterConfig.js";
import { createAdapter, type AdapterConfig } from "./adapterConfig.js";
import { ReviewActionConflictError, SessionStore, sessionStore } from "./sessionStore.js";
import { communityNetwork, type CommunityNetwork } from "../community/network.js";
import {
  USER_BLOCKED_MESSAGE_CODE,
  USER_CONFIRMED_LEGITIMATE_CODE,
} from "../community/feedback.js";
import { isSharedMailboxDomain } from "../engine/identitySignals.js";
import {
  moveMessagesToTrash,
  normalizeSenderAddress,
  normalizeSenderDomain,
} from "../workflows/blockAndCleanup.js";
import { reportMessagesAsSpam } from "../workflows/reportSpam.js";
import { executeOneClickUnsubscribe } from "../workflows/unsubscribe.js";
import type { CommunityReportContext, CommunityReportReceipt } from "../community/types.js";
import { localOperationalMetrics } from "./localOperationalMetrics.js";
import type { AccountPlatformService } from "../platform/accountFamilyService.js";
import type {
  ConsumerActivityRecord,
  ConsumerStateRepository,
} from "./consumerStatePersistence.js";
import { defaultConsumerStateRepository } from "./defaultConsumerStateRepository.js";

const ACTIVITY_UNDO_WINDOW_MS = 30 * 60 * 1_000;

export interface ProtectionActionRouteDependencies {
  sessions?: SessionStore;
  community?: CommunityNetwork;
  adapterFactory?: (config: AdapterConfig | SecureAdapterConfig) => EmailAdapter;
  familyThreats?: Pick<AccountPlatformService, "recordFamilyThreat">;
  consumerActivity?: Pick<ConsumerStateRepository, "appendActivity">;
}

function actionError(error: unknown): { status: number; message: string } {
  return {
    status: error instanceof ReviewActionConflictError ? 409 : 400,
    message: error instanceof Error ? error.message : String(error),
  };
}

function noStore(res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

function senderDomain(address: string): string {
  return normalizeSenderDomain(address.slice(address.lastIndexOf("@") + 1));
}

function blockLearningContext(context: CommunityReportContext): CommunityReportContext {
  return {
    ...structuredClone(context),
    evidenceCodes: [...new Set([...context.evidenceCodes, USER_BLOCKED_MESSAGE_CODE])].sort(),
  };
}

function legitimateLearningContext(context: CommunityReportContext): CommunityReportContext {
  return {
    campaignFingerprint: context.campaignFingerprint,
    indicators: structuredClone(context.indicators),
    evidenceCodes: [USER_CONFIRMED_LEGITIMATE_CODE],
    evidenceScore: 0,
    verdict: "safe",
  };
}

function reversibleProviderAction(
  session: NonNullable<ReturnType<SessionStore["get"]>>,
  providerNativeId: string,
): ConsumerActivityRecord["undo"] {
  const provider = session.config.provider;
  if (session.config.mode !== "fixture" && provider !== "gmail" && provider !== "outlook") return null;
  return {
    providerNativeIds: [providerNativeId],
    expiresAt: Date.now() + ACTIVITY_UNDO_WINDOW_MS,
    usedAt: null,
  };
}

function recordActivity(
  dependencies: ProtectionActionRouteDependencies,
  session: NonNullable<ReturnType<SessionStore["get"]>>,
  input: Omit<ConsumerActivityRecord, "activityId" | "createdAt" | "provider">,
): boolean {
  const activity = dependencies.consumerActivity ?? defaultConsumerStateRepository;
  try {
    activity.appendActivity(session.policyAccountKey, {
      ...input,
      provider: session.config.provider,
    });
    return true;
  } catch {
    // The mailbox/policy side effect is already committed at this point and
    // must never be rolled back because secondary local history could not be
    // appended (for example, disk-full after the provider accepted a move).
    return false;
  }
}

async function moveCurrentMessageToTrash(
  session: NonNullable<ReturnType<SessionStore["get"]>>,
  providerNativeId: string,
  adapterFactory: ProtectionActionRouteDependencies["adapterFactory"],
): Promise<{ movedCurrent: boolean; moveError?: string }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 35_000);
  const adapter = (adapterFactory ?? createAdapter)(session.config);
  try {
    await adapter.connect(controller.signal);
    const result = await moveMessagesToTrash(adapter, [providerNativeId], controller.signal);
    if (result.moved !== 1 || result.failed.length) {
      return {
        movedCurrent: false,
        moveError: result.failed[0]?.reason ?? "The provider did not confirm the Trash move.",
      };
    }
    return { movedCurrent: true };
  } catch (error) {
    return {
      movedCurrent: false,
      moveError: error instanceof Error ? error.message : String(error),
    };
  } finally {
    clearTimeout(timeout);
    await adapter.disconnect().catch(() => undefined);
  }
}

async function submitLearning(
  community: CommunityNetwork,
  context: CommunityReportContext,
  accountKey: string,
): Promise<CommunityReportReceipt | null> {
  try {
    return await community.submit(context, accountKey);
  } catch {
    return null;
  }
}

function familyStatus(
  dependencies: ProtectionActionRouteDependencies,
  mailboxAccountKey: string,
  campaignFingerprint: string,
  source: "report_scam" | "family_block",
): { shared: boolean; status?: string; error?: string } {
  if (!dependencies.familyThreats) return { shared: false };
  try {
    const snapshot = dependencies.familyThreats.recordFamilyThreat(mailboxAccountKey, campaignFingerprint, source);
    const status = snapshot?.entries.find((entry) => entry.campaignFingerprint === campaignFingerprint)?.status;
    return snapshot ? { shared: true, status } : { shared: false };
  } catch (error) {
    return { shared: false, error: error instanceof Error ? error.message : String(error) };
  }
}

export function registerProtectionActionRoutes(
  app: Express,
  dependencies: ProtectionActionRouteDependencies = {},
): void {
  const sessions = dependencies.sessions ?? sessionStore;
  const community = dependencies.community ?? communityNetwork;

  const block = (scope: "sender" | "domain") => async (req: Request, res: Response) => {
    const session = sessions.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });

    let action;
    try {
      // The opaque scan token, not a browser-supplied address/domain, owns the
      // mutation. Duplicate/stale tabs share one atomic 409 boundary.
      action = sessions.claimReviewAction(session, (req.body as { token?: unknown }).token, "trash");
    } catch (error) {
      const detail = actionError(error);
      return res.status(detail.status).json({ error: detail.message });
    }

    if (!action.senderAddress) {
      sessions.releaseReviewAction(action, "trash");
      return res.status(400).json({ error: "This message does not contain a usable sender address." });
    }

    const address = normalizeSenderAddress(action.senderAddress);
    const value = scope === "sender" ? address : senderDomain(address);
    if (scope === "domain" && isSharedMailboxDomain(value)) {
      sessions.releaseReviewAction(action, "trash");
      return res.status(409).json({
        error: `Domain-wide blocking is disabled for shared mailbox domain ${value}. Block the exact sender instead.`,
      });
    }

    try {
      sessions.mutateAndPersistPersonalPolicy(session, (policy) => {
        if (scope === "sender") policy.blockSender(value);
        else policy.blockDomain(value);
      });
    } catch (error) {
      sessions.releaseReviewAction(action, "trash");
      return res.status(500).json({
        error: `${scope === "sender" ? "Sender" : "Domain"} block was not saved: ${error instanceof Error ? error.message : String(error)}`,
      });
    }

    const move = await moveCurrentMessageToTrash(session, action.providerNativeId, dependencies.adapterFactory);
    if (!move.movedCurrent) {
      // The durable block is already authoritative and must never be rolled
      // back because a provider move was transiently unavailable. Releasing
      // the token permits an explicit retry of the current-message disposal.
      sessions.releaseReviewAction(action, "trash");
    }

    const learning = await submitLearning(
      community,
      blockLearningContext(action.communityReport),
      session.policyAccountKey,
    );
    const shareWithFamily = (req.body as { shareWithFamily?: unknown }).shareWithFamily === true;
    const family = shareWithFamily
      ? familyStatus(dependencies, session.policyAccountKey, action.communityReport.campaignFingerprint, "family_block")
      : { shared: false };
    recordActivity(dependencies, session, {
      kind: "blocked",
      severity: "warning",
      title: scope === "sender" ? "Sender blocked" : "Sender domain blocked",
      detail: move.movedCurrent
        ? "A personal protection rule was saved and the current message was moved to Trash. No mailbox content was stored in Activity."
        : "A personal protection rule was saved, but the current provider move needs a retry. Future matching mail remains protected.",
      reasonCodes: [scope === "sender" ? "USER_BLOCK_SENDER" : "USER_BLOCK_DOMAIN"],
      undo: null,
    });

    noStore(res);
    return res.status(move.movedCurrent ? 200 : 207).json({
      blocked: true,
      persisted: sessions.personalPolicyPersistent(),
      scope,
      value,
      accountId: session.id,
      token: action.token,
      movedCurrent: move.movedCurrent,
      moveError: move.moveError,
      family,
      learning: learning ? {
        accepted: learning.accepted,
        delivery: learning.delivery,
        status: learning.status,
        independentReporters: learning.independentReporters,
      } : { accepted: false },
    });
  };

  app.post("/api/accounts/:id/messages/block-sender", block("sender"));
  app.post("/api/accounts/:id/messages/block-domain", block("domain"));

  app.post("/api/accounts/:id/messages/mark-safe", (req: Request, res: Response) => {
    const session = sessions.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    let action;
    try { action = sessions.claimReviewAction(session, (req.body as { token?: unknown }).token, "mark_safe"); }
    catch (error) { const detail = actionError(error); return res.status(detail.status).json({ error: detail.message }); }

    try {
      sessions.mutateAndPersistPersonalPolicy(session, (policy) => policy.approveException(action.exceptionKey));
      localOperationalMetrics.recordFalsePositiveApproval();
      recordActivity(dependencies, session, {
        kind: "settings",
        severity: "info",
        title: "Message marked Safe",
        detail: "An exact-message local exception was saved. It cannot suppress future independent hard-threat evidence from other messages.",
        reasonCodes: ["USER_MARKED_MESSAGE_SAFE"],
        undo: null,
      });
      noStore(res);
      return res.json({ markedSafe: true, persisted: sessions.personalPolicyPersistent(), scope: "message", accountId: session.id, token: action.token });
    } catch (error) {
      sessions.releaseReviewAction(action, "mark_safe");
      return res.status(500).json({ error: `Message approval was not saved: ${error instanceof Error ? error.message : String(error)}` });
    }
  });

  app.post("/api/accounts/:id/messages/trust-sender", (req: Request, res: Response) => {
    const session = sessions.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    let action;
    try { action = sessions.claimReviewAction(session, (req.body as { token?: unknown }).token, "trust_sender"); }
    catch (error) { const detail = actionError(error); return res.status(detail.status).json({ error: detail.message }); }
    if (!action.senderAddress) {
      sessions.releaseReviewAction(action, "trust_sender");
      return res.status(400).json({ error: "This message does not contain a usable sender address." });
    }
    try {
      sessions.mutateAndPersistPersonalPolicy(session, (policy) => policy.trustSender(action.senderAddress!));
      recordActivity(dependencies, session, {
        kind: "settings",
        severity: "info",
        title: "Sender trust preference saved",
        detail: "The sender was added to the account-local trusted list. Trusted status never overrides hard authentication or verified threat evidence.",
        reasonCodes: ["USER_TRUSTED_SENDER"],
        undo: null,
      });
      noStore(res);
      return res.json({ trusted: true, persisted: sessions.personalPolicyPersistent(), scope: "sender", value: action.senderAddress, accountId: session.id, token: action.token });
    } catch (error) {
      sessions.releaseReviewAction(action, "trust_sender");
      return res.status(500).json({ error: `Trusted sender was not saved: ${error instanceof Error ? error.message : String(error)}` });
    }
  });

  app.post("/api/accounts/:id/messages/trash", async (req: Request, res: Response) => {
    const session = sessions.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    let action;
    try { action = sessions.claimReviewAction(session, (req.body as { token?: unknown }).token, "trash"); }
    catch (error) { const detail = actionError(error); return res.status(detail.status).json({ error: detail.message }); }

    const move = await moveCurrentMessageToTrash(session, action.providerNativeId, dependencies.adapterFactory);
    if (!move.movedCurrent) {
      sessions.releaseReviewAction(action, "trash");
      noStore(res);
      return res.status(502).json({ error: move.moveError ?? "The provider did not confirm the Trash move.", accountId: session.id, token: action.token });
    }
    recordActivity(dependencies, session, {
      kind: "quarantined",
      severity: "info",
      title: "Message moved to Trash",
      detail: "The selected message was moved to Trash. Undo is offered only when the provider preserves a stable message identity.",
      reasonCodes: ["USER_MOVE_TO_TRASH"],
      undo: reversibleProviderAction(session, action.providerNativeId),
    });
    noStore(res);
    return res.json({ moved: 1, failed: [], success: true, accountId: session.id, token: action.token });
  });

  app.post("/api/accounts/:id/messages/report-spam", async (req: Request, res: Response) => {
    const session = sessions.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    let action;
    try { action = sessions.claimReviewAction(session, (req.body as { token?: unknown }).token, "report_spam"); }
    catch (error) { const detail = actionError(error); return res.status(detail.status).json({ error: detail.message }); }
    if (action.normalizedFolder === "spam") {
      sessions.releaseReviewAction(action, "report_spam");
      return res.status(409).json({ error: "This message is already in the provider Spam/Junk folder." });
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 35_000);
    const adapter = (dependencies.adapterFactory ?? createAdapter)(session.config);
    let committed = false;
    try {
      await adapter.connect(controller.signal);
      const result = await reportMessagesAsSpam(adapter, [action.providerNativeId], controller.signal);
      if (result.reported !== 1 || result.failed.length) {
        return res.status(502).json({ ...result, error: result.failed[0]?.reason ?? "The provider did not confirm the Spam/Junk action.", accountId: session.id, token: action.token });
      }
      committed = true;
      recordActivity(dependencies, session, {
        kind: "quarantined",
        severity: "attention",
        title: "Message moved to Spam/Junk",
        detail: "The selected message was moved using the provider Spam/Junk action. This did not submit an Email Shield scam report.",
        reasonCodes: ["USER_MOVE_TO_SPAM"],
        undo: reversibleProviderAction(session, action.providerNativeId),
      });
      noStore(res);
      return res.json({ ...result, success: true, accountId: session.id, token: action.token });
    } catch (error) {
      return res.status(502).json({ error: `Move to Spam/Junk failed: ${error instanceof Error ? error.message : String(error)}`, accountId: session.id, token: action.token });
    } finally {
      if (!committed) sessions.releaseReviewAction(action, "report_spam");
      clearTimeout(timeout);
      await adapter.disconnect().catch(() => undefined);
    }
  });

  app.post("/api/accounts/:id/messages/unsubscribe", async (req: Request, res: Response) => {
    const session = sessions.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    let action;
    try { action = sessions.resolveUnsubscribeAction(session, (req.body as { token?: unknown }).token); }
    catch (error) { return res.status(400).json({ error: error instanceof Error ? error.message : String(error) }); }

    if (action.method === "link_only" || action.method === "mailto") {
      noStore(res);
      return res.json({ success: true, manualAction: true, method: action.method, target: action.target, accountId: session.id, actionKey: action.actionKey });
    }
    if (session.personalPolicy.isUnsubscribedAction(action.actionKey)) {
      noStore(res);
      return res.json({ success: true, alreadyUnsubscribed: true, method: action.method, accountId: session.id, actionKey: action.actionKey });
    }

    const result = await executeOneClickUnsubscribe(action.target);
    if (!result.success) {
      return res.status(502).json({ ...result, error: result.reason ?? "The unsubscribe endpoint did not confirm success.", accountId: session.id, actionKey: action.actionKey });
    }
    try { sessions.markUnsubscribed(session, action.actionKey); }
    catch (error) {
      return res.status(500).json({ error: `Unsubscribe succeeded but local status was not saved: ${error instanceof Error ? error.message : String(error)}` });
    }
    recordActivity(dependencies, session, {
      kind: "unsubscribed",
      severity: "info",
      title: "One-click unsubscribe completed",
      detail: "The verified one-click unsubscribe endpoint confirmed success and the local action status was saved.",
      reasonCodes: ["RFC8058_UNSUBSCRIBE_SUCCESS"],
      undo: null,
    });
    noStore(res);
    return res.json({ ...result, method: action.method, accountId: session.id, actionKey: action.actionKey, alreadyUnsubscribed: false });
  });

  app.post("/api/accounts/:id/messages/report-scam", async (req: Request, res: Response) => {
    const session = sessions.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });

    let action;
    try {
      action = sessions.claimReviewAction(session, (req.body as { token?: unknown }).token, "report_scam");
    } catch (error) {
      const detail = actionError(error);
      return res.status(detail.status).json({ error: detail.message });
    }

    const blockSender = (req.body as { blockSender?: unknown }).blockSender === true;
    try {
      sessions.mutateAndPersistPersonalPolicy(session, (policy) => {
        policy.reportCampaign(action.communityReport.campaignFingerprint);
        if (blockSender && action.senderAddress) policy.blockSender(action.senderAddress);
      });
    } catch (error) {
      sessions.releaseReviewAction(action, "report_scam");
      return res.status(500).json({
        error: `Local scam protection was not saved: ${error instanceof Error ? error.message : String(error)}`,
      });
    }

    // Family sharing is privacy-reduced and separate from the public community
    // service. A local report automatically enters the member's private circle
    // when this mailbox has been linked to a Family Shield account.
    const family = familyStatus(
      dependencies,
      session.policyAccountKey,
      action.communityReport.campaignFingerprint,
      "report_scam",
    );

    // Local campaign protection is committed before any network/provider side
    // effect. Even if either service is temporarily unavailable, every future
    // matching message remains a local Confirmed Threat and will auto-Trash.
    const move = await moveCurrentMessageToTrash(session, action.providerNativeId, dependencies.adapterFactory);

    let receipt: CommunityReportReceipt | null = null;
    let communityError: string | undefined;
    try {
      receipt = await community.submit(action.communityReport, session.policyAccountKey);
      localOperationalMetrics.recordAbuseReport(true);
    } catch (error) {
      localOperationalMetrics.recordAbuseReport(false);
      communityError = error instanceof Error ? error.message : String(error);
    }

    recordActivity(dependencies, session, {
      kind: "reported",
      severity: "critical",
      title: "Scam report protected locally",
      detail: `${move.movedCurrent ? "The current message was moved to Trash. " : "The current provider move needs a retry. "}${receipt?.accepted ? "Privacy-reduced community evidence was accepted. " : "Community delivery was unavailable or not accepted. "}${family.shared ? "Family Shield received the private campaign signal." : "No Family Shield campaign share was completed."}`,
      reasonCodes: ["USER_REPORTED_SCAM", ...(blockSender ? ["USER_BLOCK_SENDER"] : [])],
      undo: null,
    });

    const complete = move.movedCurrent && receipt?.accepted === true && !family.error;
    noStore(res);
    return res.status(complete ? 200 : 207).json({
      success: true,
      localProtected: true,
      senderBlocked: Boolean(blockSender && action.senderAddress),
      accountId: session.id,
      token: action.token,
      movedCurrent: move.movedCurrent,
      moveError: move.moveError,
      family,
      communityAccepted: receipt?.accepted === true,
      communityError,
      pendingReports: community.pendingReports(),
      ...(receipt ?? {
        accepted: false,
        queued: false,
        campaignFingerprint: action.communityReport.campaignFingerprint,
        independentReporters: 0,
        status: "candidate" as const,
        feedUpdated: false,
      }),
    });
  });

  app.post("/api/accounts/:id/messages/legitimate-feedback", async (req: Request, res: Response) => {
    const session = sessions.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });

    let action;
    try {
      // A positive campaign decision and Report Scam are mutually exclusive for
      // the same stale scan card. A rescan is required to reverse that judgment.
      action = sessions.claimReviewAction(session, (req.body as { token?: unknown }).token, "report_scam");
    } catch (error) {
      const detail = actionError(error);
      return res.status(detail.status).json({ error: detail.message });
    }

    try {
      const receipt = await community.submit(
        legitimateLearningContext(action.communityReport),
        session.policyAccountKey,
      );
      recordActivity(dependencies, session, {
        kind: "settings",
        severity: "info",
        title: "Legitimate feedback submitted",
        detail: "A privacy-reduced legitimate-signal correction was submitted. It cannot override hard authentication failures or verified confirmed threats.",
        reasonCodes: ["USER_CONFIRMED_LEGITIMATE"],
        undo: null,
      });
      noStore(res);
      return res.json({
        accepted: true,
        accountId: session.id,
        token: action.token,
        delivery: receipt.delivery,
        status: receipt.status,
        independentReporters: receipt.independentReporters,
      });
    } catch (error) {
      sessions.releaseReviewAction(action, "report_scam");
      noStore(res);
      return res.status(502).json({
        error: `Legitimate feedback could not be queued: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  });
}
