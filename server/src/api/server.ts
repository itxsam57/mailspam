import express from "express";
import type { Request, Response } from "express";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ReviewActionConflictError, sessionStore } from "./sessionStore.js";
import { createAdapter, type AdapterConfig } from "./adapterConfig.js";
import { Worker } from "node:worker_threads";
import {
  moveMessagesToTrash,
  normalizeSenderAddress,
  normalizeSenderDomain,
} from "../workflows/blockAndCleanup.js";
import { reportMessagesAsSpam } from "../workflows/reportSpam.js";
import {
  executeOneClickUnsubscribe,
  normalizeManualUnsubscribeTarget,
  normalizeOneClickTarget,
} from "../workflows/unsubscribe.js";
import {
  analyzeLinks,
  destinationAnalysisCoordinator,
  type DestinationAnalysisCoordinator,
} from "../workflows/analyzeLinks.js";
import type { Provider } from "../canonical/envelope.js";
import type { ScanActionContext, ScanProgress } from "../workflows/scanWorkflows.js";
import { runDeveloperTestSuite } from "../devtools/testSuiteRunner.js";
import { communityNetwork, type CommunityNetwork } from "../community/network.js";
import type { CommunityReportSubmission } from "../community/types.js";
import { localOperationalMetrics } from "./localOperationalMetrics.js";
import { publicScanProgress } from "./scanStream.js";
import {
  noFixtureConnectionPersistence,
  type FixtureConnectionPersistence,
} from "./fixtureConnectionPersistence.js";
import { dashboardScriptTags } from "./dashboardScripts.js";

export function createServer(options: {
  community?: CommunityNetwork;
  destinationAnalyzer?: DestinationAnalysisCoordinator;
  fixtureConnections?: FixtureConnectionPersistence;
} = {}) {
  const app = express();
  const community = options.community ?? communityNetwork;
  const destinationAnalyzer = options.destinationAnalyzer ?? destinationAnalysisCoordinator;
  const fixtureConnections = options.fixtureConnections ?? noFixtureConnectionPersistence;
  app.use(express.json({ limit: "64kb" }));

  const reviewActionError = (error: unknown) => ({
    status: error instanceof ReviewActionConflictError ? 409 : 400,
    message: error instanceof Error ? error.message : String(error),
  });

  const __dirname = dirname(fileURLToPath(import.meta.url));
  const webDir = join(__dirname, "../../../web");
  const dashboardHtml = readFileSync(join(webDir, "index.html"), "utf8").replace(
    "</body>",
    `${dashboardScriptTags(false)}</body>`,
  );
  app.get("/", (_req, res) => res.type("html").send(dashboardHtml));
  app.use(express.static(webDir));

  app.get("/api/community/v1/status", (_req: Request, res: Response) => {
    const entries = community.getVerifiedEntries();
    res.json({
      clientEnabled: true,
      remoteConfigured: Boolean(community.remoteUrl),
      aggregationServerEnabled: community.serverEnabled,
      verifiedFeedAvailable: entries !== null,
      verifiedFeedEntries: entries?.length ?? 0,
      pendingReports: community.pendingReports(),
    });
  });

  app.post("/api/community/v1/report", (req: Request, res: Response) => {
    try {
      const receipt = community.acceptExternalReport(req.body as CommunityReportSubmission);
      res.setHeader("Cache-Control", "no-store");
      res.json(receipt);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const status = message.includes("disabled") ? 404 : message.includes("rate limit") ? 429 : 400;
      res.status(status).json({ error: message });
    }
  });

  app.get("/api/community/v1/feed", (_req: Request, res: Response) => {
    try {
      const feed = community.signedFeed();
      res.setHeader("Cache-Control", "public, max-age=300");
      res.json(feed);
    } catch (error) {
      res.status(404).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.get("/api/community/v1/public-key", (_req: Request, res: Response) => {
    const info = community.publicInfo();
    if (!info.enabled) return res.status(404).json({ error: "Community aggregation service is disabled on this instance." });
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.json(info);
  });

  app.post("/api/accounts/connect", async (req: Request, res: Response) => {
    const { provider, mode, credentials = {}, label } = req.body as {
      provider: Provider;
      mode: "fixture" | "live";
      credentials?: Record<string, string>;
      label?: string;
    };
    try {
      let config: AdapterConfig;
      if (mode === "fixture") config = { provider, mode };
      else if (provider === "gmail") config = { provider, mode, credentials: { clientId: credentials.clientId ?? "", clientSecret: credentials.clientSecret ?? "", refreshToken: credentials.refreshToken ?? "" } };
      else if (provider === "outlook") config = { provider, mode, credentials: { clientId: credentials.clientId ?? "", clientSecret: credentials.clientSecret ?? "", tenantId: credentials.tenantId ?? "common", refreshToken: credentials.refreshToken ?? "" } };
      else if (provider === "icloud" || provider === "yahoo") config = { provider, mode, credentials: { user: credentials.user ?? "", appPassword: credentials.appPassword ?? "" } };
      else config = { provider: "imap", mode, credentials: { host: credentials.host ?? "", port: Number(credentials.port ?? 993), secure: credentials.secure !== "false", user: credentials.user ?? "", appPassword: credentials.appPassword ?? "" } };

      const adapter = createAdapter(config);
      const ac = new AbortController();
      const timeout = setTimeout(() => ac.abort(), 35_000);
      try {
        await adapter.connect(ac.signal);
        await adapter.listFolders(ac.signal);
      } finally {
        clearTimeout(timeout);
        await adapter.disconnect();
      }

      // Validation above uses the submitted credential transiently. Only after
      // the provider confirms it do we create the long-lived account session;
      // Windows app passwords must enter Credential Manager here or the
      // connection fails rather than silently degrading to persisted plaintext.
      const session = await sessionStore.createSecured(provider, label ?? `${provider} (${mode})`, config);
      if (mode === "fixture") {
        try { fixtureConnections.remember(provider); }
        catch (error) {
          await sessionStore.remove(session.id);
          throw error;
        }
      }
      const policy = session.personalPolicy.snapshot();
      res.json({
        accountId: session.id,
        provider: session.provider,
        label: session.label,
        mode,
        personalPolicy: {
          persistent: sessionStore.personalPolicyPersistent(),
          blockedSenders: policy.blockedSenders.length,
          blockedDomains: policy.blockedDomains.length,
          trustedSenders: policy.trustedSenders.length,
          approvedExceptions: policy.approvedExceptions.length,
          unsubscribedActions: policy.unsubscribedActions.length,
          reportedCampaigns: policy.reportedCampaigns.length,
        },
        community: {
          remoteConfigured: Boolean(community.remoteUrl),
          pendingReports: community.pendingReports(),
          verifiedFeedEntries: community.getVerifiedEntries()?.length ?? 0,
        },
      });
    } catch (error) {
      res.status(502).json({ error: `Failed to connect: ${(error as Error).message}` });
    }
  });

  app.get("/api/accounts", (_req: Request, res: Response) => {
    res.json(sessionStore.list().map((session) => ({
      accountId: session.id,
      provider: session.provider,
      label: session.label,
    })));
  });

  app.delete("/api/accounts/:id", async (req: Request, res: Response) => {
    const before = sessionStore.list();
    fixtureConnections.synchronize(before.filter((session) => session.id !== req.params.id));
    try { await sessionStore.remove(req.params.id!); }
    catch (error) { fixtureConnections.synchronize(before); throw error; }
    res.status(204).send();
  });

  function sseHeaders(res: Response) {
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    });
  }

  function registerPublicActions(session: NonNullable<ReturnType<typeof sessionStore.get>>, context: ScanActionContext) {
    const reviewAction = sessionStore.registerReviewAction(session, context);
    let unsubscribeAction: Record<string, unknown> = { available: false, method: "none" };
    const capability = context.unsubscribe;

    if (capability.available && capability.method !== "none" && capability.target) {
      try {
        const target = capability.method === "one_click_post"
          ? normalizeOneClickTarget(capability.target)
          : normalizeManualUnsubscribeTarget(capability.method, capability.target);
        unsubscribeAction = {
          available: true,
          method: capability.method,
          source: capability.source,
          ...sessionStore.registerUnsubscribeAction(
            session,
            capability.method,
            target,
            context.providerNativeId,
          ),
        };
      } catch {
        unsubscribeAction = { available: false, method: "none" };
      }
    }

    return { reviewAction, unsubscribeAction };
  }

  app.get("/api/accounts/:id/scan/:type", async (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    const type = req.params.type as "quick" | "full" | "spam";
    if (!["quick", "full", "spam"].includes(type)) return res.status(400).json({ error: "Unknown scan type" });
    if (session.activeScanWorker) return res.status(409).json({ error: "A scan is already active" });

    sessionStore.clearScanActions(session);
    sseHeaders(res);
    res.flushHeaders();
    res.write(`event: scan-started\ndata: ${JSON.stringify({ type, provider: session.provider })}\n\n`);
    res.write(`event: scan-status\ndata: ${JSON.stringify({ phase: "community_feed", message: "Refreshing verified community protection feed…" })}\n\n`);
    await community.refreshFeed();

    const workerUrl = new URL("../workers/scanWorker.js", import.meta.url);
    const liveImap = session.config.mode === "live" && ["icloud", "yahoo", "imap"].includes(session.provider);
    const pageSize = liveImap ? 10 : 20;

    let worker: Worker;
    try {
      worker = new Worker(workerUrl, {
        workerData: {
          config: session.config,
          type,
          pageSize,
          personalPolicy: session.personalPolicy.snapshot(),
          threatFeedEntries: community.getVerifiedEntries(),
        },
      });
    } catch (error) {
      res.write(`event: scan-error\ndata: ${JSON.stringify({ message: `Could not start scan worker: ${(error as Error).message}` })}\n\n`);
      res.end();
      return;
    }

    session.activeScanWorker = worker;
    let finished = false;
    let terminalEventSent = false;

    const writeEvent = (event: string, data: unknown) => {
      if (!res.writableEnded && !res.destroyed) {
        res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
      }
    };

    const cleanup = () => {
      if (finished) return;
      finished = true;
      if (session.activeScanWorker === worker) session.activeScanWorker = null;
      if (!res.writableEnded) res.end();
    };

    worker.on("message", (message) => {
      if (message.type === "status") writeEvent("scan-status", message.status);
      else if (message.type === "progress") {
        const progress = message.progress as { suspiciousCards?: any[]; diagnosticSummaries?: any[] };
        const actionsByNativeId = new Map<string, ReturnType<typeof registerPublicActions>>();

        for (const summary of progress.diagnosticSummaries ?? []) {
          const context = summary.actionContext as ScanActionContext | undefined;
          if (!context) continue;
          const actions = registerPublicActions(session, context);
          actionsByNativeId.set(context.providerNativeId, actions);
          summary.reviewAction = actions.reviewAction;
          summary.unsubscribeAction = actions.unsubscribeAction;
          delete summary.actionContext;
        }

        for (const result of progress.suspiciousCards ?? []) {
          const actions = actionsByNativeId.get(result.envelope.providerNativeId);
          if (actions) {
            result.reviewAction = actions.reviewAction;
            result.unsubscribeAction = actions.unsubscribeAction;
          }

          result.envelope.listHeaders = {
            listId: result.envelope.listHeaders?.listId ?? null,
            listUnsubscribe: null,
            listUnsubscribePost: null,
          };
        }
        if (!res.writableEnded && !res.destroyed) res.write(`data: ${JSON.stringify(publicScanProgress(progress as ScanProgress))}\n\n`);
      } else if (message.type === "complete") {
        terminalEventSent = true;
        writeEvent("scan-complete", {});
        cleanup();
      } else if (message.type === "error") {
        terminalEventSent = true;
        writeEvent("scan-error", { message: message.message, name: message.name });
        cleanup();
      }
    });

    worker.on("error", (error) => {
      terminalEventSent = true;
      writeEvent("scan-error", { message: error.message, name: error.name });
      cleanup();
    });

    worker.on("exit", (code) => {
      if (!terminalEventSent && !finished) {
        writeEvent("scan-error", {
          message: code === 0
            ? "Scan worker exited before returning a result."
            : `Scan worker exited unexpectedly with code ${code}.`,
        });
      }
      cleanup();
    });

    res.on("close", () => {
      if (!finished) {
        worker.postMessage({ type: "cancel" });
        setTimeout(() => { if (!finished) void worker.terminate(); }, 1000).unref();
      }
    });
  });

  app.post("/api/accounts/:id/scan/stop", async (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    const worker = session.activeScanWorker;
    if (!worker) return res.json({ stopped: true, active: false });
    worker.postMessage({ type: "cancel" });
    const hardStop = setTimeout(() => { void worker.terminate(); }, 1000);
    hardStop.unref();
    res.json({ stopped: true, active: true });
  });

  app.post("/api/accounts/:id/messages/block-sender", (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    let address: string;
    try { address = normalizeSenderAddress((req.body as { address?: unknown }).address); }
    catch (error) { return res.status(400).json({ error: error instanceof Error ? error.message : String(error) }); }

    const previous = session.personalPolicy.snapshot();
    session.personalPolicy.blockSender(address);
    try {
      sessionStore.persistPersonalPolicy(session);
      res.json({ blocked: true, persisted: sessionStore.personalPolicyPersistent(), scope: "sender", value: address, accountId: session.id });
    } catch (error) {
      session.personalPolicy.replace(previous);
      res.status(500).json({ error: `Sender block was not saved: ${error instanceof Error ? error.message : String(error)}` });
    }
  });

  app.post("/api/accounts/:id/messages/block-domain", (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    let domain: string;
    try { domain = normalizeSenderDomain((req.body as { domain?: unknown }).domain); }
    catch (error) { return res.status(400).json({ error: error instanceof Error ? error.message : String(error) }); }

    const previous = session.personalPolicy.snapshot();
    session.personalPolicy.blockDomain(domain);
    try {
      sessionStore.persistPersonalPolicy(session);
      res.json({ blocked: true, persisted: sessionStore.personalPolicyPersistent(), scope: "domain", value: domain, accountId: session.id });
    } catch (error) {
      session.personalPolicy.replace(previous);
      res.status(500).json({ error: `Domain block was not saved: ${error instanceof Error ? error.message : String(error)}` });
    }
  });

  app.post("/api/accounts/:id/messages/mark-safe", (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    let action;
    try { action = sessionStore.claimReviewAction(session, (req.body as { token?: unknown }).token, "mark_safe"); }
    catch (error) { const detail = reviewActionError(error); return res.status(detail.status).json({ error: detail.message }); }

    try {
      sessionStore.mutateAndPersistPersonalPolicy(session, (policy) => policy.approveException(action.exceptionKey));
      localOperationalMetrics.recordFalsePositiveApproval();
      res.json({
        markedSafe: true,
        persisted: sessionStore.personalPolicyPersistent(),
        scope: "message",
        accountId: session.id,
        token: action.token,
      });
    } catch (error) {
      sessionStore.releaseReviewAction(action, "mark_safe");
      res.status(500).json({ error: `Message approval was not saved: ${error instanceof Error ? error.message : String(error)}` });
    }
  });

  app.post("/api/accounts/:id/messages/trust-sender", (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    let action;
    try { action = sessionStore.claimReviewAction(session, (req.body as { token?: unknown }).token, "trust_sender"); }
    catch (error) { const detail = reviewActionError(error); return res.status(detail.status).json({ error: detail.message }); }
    if (!action.senderAddress) {
      sessionStore.releaseReviewAction(action, "trust_sender");
      return res.status(400).json({ error: "This message does not contain a usable sender address." });
    }

    try {
      sessionStore.mutateAndPersistPersonalPolicy(session, (policy) => policy.trustSender(action.senderAddress!));
      res.json({
        trusted: true,
        persisted: sessionStore.personalPolicyPersistent(),
        scope: "sender",
        value: action.senderAddress,
        accountId: session.id,
        token: action.token,
      });
    } catch (error) {
      sessionStore.releaseReviewAction(action, "trust_sender");
      res.status(500).json({ error: `Trusted sender was not saved: ${error instanceof Error ? error.message : String(error)}` });
    }
  });

  app.post("/api/accounts/:id/messages/report-scam", async (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    let action;
    try { action = sessionStore.claimReviewAction(session, (req.body as { token?: unknown }).token, "report_scam"); }
    catch (error) { const detail = reviewActionError(error); return res.status(detail.status).json({ error: detail.message }); }

    const blockSender = (req.body as { blockSender?: unknown }).blockSender === true;
    try {
      sessionStore.mutateAndPersistPersonalPolicy(session, (policy) => {
        policy.reportCampaign(action.communityReport.campaignFingerprint);
        if (blockSender && action.senderAddress) policy.blockSender(action.senderAddress);
      });
    } catch (error) {
      sessionStore.releaseReviewAction(action, "report_scam");
      return res.status(500).json({ error: `Local scam protection was not saved: ${error instanceof Error ? error.message : String(error)}` });
    }

    try {
      const receipt = await community.submit(action.communityReport, session.policyAccountKey);
      localOperationalMetrics.recordAbuseReport(true);
      res.json({
        success: true,
        localProtected: true,
        senderBlocked: Boolean(blockSender && action.senderAddress),
        accountId: session.id,
        token: action.token,
        pendingReports: community.pendingReports(),
        ...receipt,
      });
    } catch (error) {
      localOperationalMetrics.recordAbuseReport(false);
      res.status(502).json({
        error: `The campaign is protected locally, but the community report could not be queued: ${error instanceof Error ? error.message : String(error)}`,
        localProtected: true,
        senderBlocked: Boolean(blockSender && action.senderAddress),
        accountId: session.id,
        token: action.token,
      });
    }
  });

  app.get("/api/accounts/:id/personal-policy", (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    res.json({ persistent: sessionStore.personalPolicyPersistent(), ...session.personalPolicy.snapshot() });
  });

  app.post("/api/accounts/:id/messages/trash", async (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    let action;
    try { action = sessionStore.claimReviewAction(session, (req.body as { token?: unknown }).token, "trash"); }
    catch (error) { const detail = reviewActionError(error); return res.status(detail.status).json({ error: detail.message }); }
    const ac = new AbortController();
    const adapter = createAdapter(session.config);
    let committed = false;
    try {
      await adapter.connect(ac.signal);
      const result = await moveMessagesToTrash(adapter, [action.providerNativeId], ac.signal);
      committed = result.moved === 1 && result.failed.length === 0;
      if (!committed) return res.status(502).json({ ...result, error: result.failed[0]?.reason ?? "The provider did not confirm the Trash move.", accountId: session.id, token: action.token });
      res.json({ ...result, success: true, accountId: session.id, token: action.token });
    } catch (error) {
      res.status(502).json({ error: `Move to Trash failed: ${error instanceof Error ? error.message : String(error)}`, accountId: session.id, token: action.token });
    } finally {
      if (!committed) sessionStore.releaseReviewAction(action, "trash");
      await adapter.disconnect().catch(() => undefined);
    }
  });

  app.post("/api/accounts/:id/messages/report-spam", async (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });

    let action;
    try {
      action = sessionStore.claimReviewAction(session, (req.body as { token?: unknown }).token, "report_spam");
    } catch (error) {
      const detail = reviewActionError(error);
      return res.status(detail.status).json({ error: detail.message });
    }
    if (action.normalizedFolder === "spam") {
      sessionStore.releaseReviewAction(action, "report_spam");
      return res.status(409).json({ error: "This message is already in the provider Spam/Junk folder." });
    }

    const ac = new AbortController();
    const timeout = setTimeout(() => ac.abort(), 35_000);
    const adapter = createAdapter(session.config);
    let committed = false;
    try {
      await adapter.connect(ac.signal);
      const result = await reportMessagesAsSpam(adapter, [action.providerNativeId], ac.signal);
      if (result.reported !== 1 || result.failed.length) {
        return res.status(502).json({
          ...result,
          error: result.failed[0]?.reason ?? "The provider did not confirm the Spam/Junk action.",
          accountId: session.id,
          token: action.token,
        });
      }
      committed = true;
      res.json({
        ...result,
        success: true,
        accountId: session.id,
        token: action.token,
      });
    } catch (error) {
      res.status(502).json({
        error: `Move to Spam/Junk failed: ${error instanceof Error ? error.message : String(error)}`,
        accountId: session.id,
        token: action.token,
      });
    } finally {
      if (!committed) sessionStore.releaseReviewAction(action, "report_spam");
      clearTimeout(timeout);
      await adapter.disconnect();
    }
  });

  app.post("/api/accounts/:id/messages/unsubscribe", async (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });

    let action;
    try {
      action = sessionStore.resolveUnsubscribeAction(session, (req.body as { token?: unknown }).token);
    } catch (error) {
      return res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
    }

    if (action.method === "link_only" || action.method === "mailto") {
      return res.json({
        success: true,
        manualAction: true,
        method: action.method,
        target: action.target,
        accountId: session.id,
        actionKey: action.actionKey,
      });
    }

    if (session.personalPolicy.isUnsubscribedAction(action.actionKey)) {
      return res.json({
        success: true,
        alreadyUnsubscribed: true,
        method: action.method,
        accountId: session.id,
        actionKey: action.actionKey,
      });
    }

    const result = await executeOneClickUnsubscribe(action.target);
    if (!result.success) {
      return res.status(502).json({
        ...result,
        error: result.reason ?? "The unsubscribe endpoint did not confirm success.",
        accountId: session.id,
        actionKey: action.actionKey,
      });
    }

    try { sessionStore.markUnsubscribed(session, action.actionKey); }
    catch (error) {
      return res.status(500).json({ error: `Unsubscribe succeeded but local status was not saved: ${error instanceof Error ? error.message : String(error)}` });
    }
    res.json({
      ...result,
      method: action.method,
      accountId: session.id,
      actionKey: action.actionKey,
      alreadyUnsubscribed: false,
    });
  });

  app.post("/api/accounts/:id/messages/analyze-links", async (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    const { envelope } = req.body as { envelope: import("../canonical/envelope.js").CanonicalEnvelope };
    const result = await analyzeLinks(envelope, destinationAnalyzer);
    res.json(result);
  });

  app.get("/api/dev/test-suite", async (_req: Request, res: Response) => {
    const report = await runDeveloperTestSuite();
    res.json(report);
  });

  return app;
}
