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
import type { CommunityReportContext, CommunityReportReceipt } from "../community/types.js";
import { localOperationalMetrics } from "./localOperationalMetrics.js";

export interface ProtectionActionRouteDependencies {
  sessions?: SessionStore;
  community?: CommunityNetwork;
  adapterFactory?: (config: AdapterConfig | SecureAdapterConfig) => EmailAdapter;
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
      // Block is also the disposal transaction for the selected message. Using
      // the existing opaque Trash operation gives duplicate/stale tabs one
      // atomic 409 boundary without trusting sender/domain values from JS.
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

    const complete = move.movedCurrent && receipt?.accepted === true;
    noStore(res);
    return res.status(complete ? 200 : 207).json({
      success: true,
      localProtected: true,
      senderBlocked: Boolean(blockSender && action.senderAddress),
      accountId: session.id,
      token: action.token,
      movedCurrent: move.movedCurrent,
      moveError: move.moveError,
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
