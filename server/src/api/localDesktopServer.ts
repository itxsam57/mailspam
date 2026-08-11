import express from "express";
import type { Request, Response } from "express";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createServer } from "./server.js";
import { localSecurity, type LocalSecurityManager } from "./localSecurity.js";
import {
  createResumeScanStreamHandler,
  createScanStreamHandler,
  requestActiveScanStop,
} from "./scanStream.js";
import { defaultScanStateRepository } from "./defaultScanStateRepository.js";
import { sessionStore } from "./sessionStore.js";
import { registerPolicyManagementRoutes } from "./policyManagement.js";
import { communityNetwork, type CommunityNetwork } from "../community/network.js";
import { GoogleOAuthFlowManager, GOOGLE_GMAIL_MODIFY_SCOPE } from "../oauth/googleOAuthFlow.js";
import { MicrosoftOAuthFlowManager } from "../oauth/microsoftOAuthFlow.js";
import {
  MICROSOFT_MAIL_READWRITE_SCOPE,
  MICROSOFT_OFFLINE_SCOPE,
  MICROSOFT_USER_READ_SCOPE,
} from "../oauth/microsoftOAuth.js";
import {
  normalizeSenderAddress,
  normalizeSenderDomain,
} from "../workflows/blockAndCleanup.js";
import type { DestinationAnalysisCoordinator } from "../workflows/analyzeLinks.js";
import {
  createBackgroundProtectionCoordinator,
  type BackgroundProtectionCoordinator,
} from "./backgroundProtection.js";

function escapeAttribute(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]!);
}

function isScanStreamPath(path: string): boolean {
  return /^\/[^/]+\/scan\/(?:quick|full|spam|resume\/[0-9a-f-]{36})$/i.test(path);
}

function publicScanHistory(session: NonNullable<ReturnType<typeof sessionStore.get>>) {
  const resumableStatuses = new Set(["interrupted", "failed", "stopped"]);
  return defaultScanStateRepository.list(session.policyAccountKey).map((record) => ({
    scanId: record.scanId,
    type: record.type,
    status: record.status,
    startedAt: record.startedAt,
    updatedAt: record.updatedAt,
    completedAt: record.completedAt,
    counters: { ...record.counters },
    resumable: Boolean(record.checkpoint && resumableStatuses.has(record.status)),
  }));
}

export function createLocalDesktopServer(options: {
  community?: CommunityNetwork;
  security?: LocalSecurityManager;
  googleOAuth?: GoogleOAuthFlowManager;
  microsoftOAuth?: MicrosoftOAuthFlowManager;
  destinationAnalyzer?: DestinationAnalysisCoordinator;
  backgroundProtection?: BackgroundProtectionCoordinator;
} = {}) {
  const app = express();
  const security = options.security ?? localSecurity;
  const community = options.community ?? communityNetwork;
  const backgroundProtection = options.backgroundProtection ?? createBackgroundProtectionCoordinator(community);
  const googleOAuth = options.googleOAuth ?? new GoogleOAuthFlowManager({
    clientId: process.env.EMAIL_SHIELD_GOOGLE_CLIENT_ID?.trim() ?? "",
    sessionStore,
  });
  const microsoftOAuth = options.microsoftOAuth ?? new MicrosoftOAuthFlowManager({
    clientId: process.env.EMAIL_SHIELD_MICROSOFT_CLIENT_ID?.trim() ?? "",
    sessionStore,
  });
  const inner = createServer({ community, destinationAnalyzer: options.destinationAnalyzer });
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const webDir = join(__dirname, "../../../web");
  const dashboardTemplate = readFileSync(join(webDir, "index.html"), "utf8");

  app.disable("x-powered-by");
  app.use(security.validateLoopbackRequest);
  app.use(security.securityHeaders);
  app.use(express.json({ limit: "64kb" }));
  app.use(security.redactResponses());

  app.get("/", (req: Request, res: Response) => {
    const context = security.openDashboard(req, res);
    const csrf = escapeAttribute(context.csrfToken);
    const nonce = escapeAttribute(context.cspNonce);
    const html = dashboardTemplate
      .replace(
        "</head>",
        `<meta name="email-shield-csrf" content="${csrf}"><script src="/local-security.js"></script></head>`,
      )
      .replace(/<script>(\s*const API\s*=)/, `<script nonce="${nonce}">$1`)
      .replace(
        "</body>",
        '<script src="/scan-monitor.js"></script><script src="/scan-history.js"></script><script src="/background-protection.js"></script><script src="/unsubscribe-monitor.js"></script><script src="/gmail-oauth.js"></script><script src="/outlook-oauth.js"></script><script src="/account-disconnect.js"></script><script src="/policy-management.js"></script></body>',
      );

    res.setHeader("Referrer-Policy", "same-origin");
    res.setHeader(
      "Content-Security-Policy",
      [
        "default-src 'self'",
        `script-src 'self' 'nonce-${context.cspNonce}'`,
        "style-src 'self' 'unsafe-inline'",
        "font-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
      ].join("; "),
    );
    res.type("html").send(html);
  });

  app.post(
    "/api/security/mutation-token",
    security.requireProtectedRead(),
    security.requireSameOrigin(),
    (req: Request, res: Response) => security.issueMutationNonce(req, res),
  );

  app.use("/api/accounts", (req: Request, res: Response, next) => {
    if (req.method === "GET" && isScanStreamPath(req.path)) {
      security.requireScanSource()(req, res, next);
      return;
    }
    if (req.method === "GET" || req.method === "HEAD") {
      security.requireProtectedRead()(req, res, next);
      return;
    }
    security.requireMutation()(req, res, next);
  });

  app.use("/api/accounts/connect", (req: Request, res: Response, next) => {
    if (!security.enforceRouteLimit(req, res, "account-connect", 12)) return;
    next();
  });

  app.get("/api/accounts/oauth/google/config", (_req: Request, res: Response) => {
    res.setHeader("Cache-Control", "no-store");
    res.json({
      configured: googleOAuth.configured(),
      flow: "desktop-loopback-pkce-s256",
      permissions: {
        identity: ["openid", "email"],
        gmail: [GOOGLE_GMAIL_MODIFY_SCOPE],
      },
      incrementalAuthorization: false,
    });
  });

  app.post("/api/accounts/oauth/google/start", async (req: Request, res: Response) => {
    if (!security.enforceRouteLimit(req, res, "google-oauth-start", 6)) return;
    try {
      const result = await googleOAuth.start();
      res.setHeader("Cache-Control", "no-store");
      res.json(result);
    } catch (error) {
      res.status(503).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.get("/api/accounts/oauth/google/status/:flowId", (req: Request, res: Response) => {
    res.setHeader("Cache-Control", "no-store");
    const status = googleOAuth.status(req.params.flowId!);
    res.status(status.status === "error" && status.error.startsWith("Unknown") ? 404 : 200).json(status);
  });

  app.get("/api/accounts/oauth/microsoft/config", (_req: Request, res: Response) => {
    res.setHeader("Cache-Control", "no-store");
    res.json({
      configured: microsoftOAuth.configured(),
      flow: "desktop-loopback-pkce-s256-public-client",
      clientType: "public",
      permissions: [MICROSOFT_OFFLINE_SCOPE, MICROSOFT_USER_READ_SCOPE, MICROSOFT_MAIL_READWRITE_SCOPE],
      disconnect: "local-protected-token-removal",
    });
  });

  app.post("/api/accounts/oauth/microsoft/start", async (req: Request, res: Response) => {
    if (!security.enforceRouteLimit(req, res, "microsoft-oauth-start", 6)) return;
    try {
      const result = await microsoftOAuth.start();
      res.setHeader("Cache-Control", "no-store");
      res.json(result);
    } catch (error) {
      res.status(503).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.get("/api/accounts/oauth/microsoft/status/:flowId", (req: Request, res: Response) => {
    res.setHeader("Cache-Control", "no-store");
    const status = microsoftOAuth.status(req.params.flowId!);
    res.status(status.status === "error" && status.error.startsWith("Unknown") ? 404 : 200).json(status);
  });

  app.delete("/api/accounts/:id", async (req: Request, res: Response) => {
    const id = req.params.id!;
    const session = sessionStore.get(id);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    if (session.activeScanWorker) requestActiveScanStop(id);
    try {
      await sessionStore.remove(id);
      backgroundProtection.remove(session.policyAccountKey);
      res.status(204).send();
    } catch (error) {
      res.status(502).json({
        error: `Account disconnect could not be completed: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  });

  app.get("/api/accounts/:id/background-protection", (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    try {
      res.setHeader("Cache-Control", "no-store");
      res.json(backgroundProtection.status(session.policyAccountKey));
    } catch (error) {
      res.status(500).json({ error: `Background protection status could not be read: ${error instanceof Error ? error.message : String(error)}` });
    }
  });

  app.post("/api/accounts/:id/background-protection", (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    const body = req.body as Record<string, unknown>;
    if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).some((key) => !["enabled", "intervalMinutes"].includes(key))) {
      return res.status(400).json({ error: "Background protection settings are invalid." });
    }
    if (typeof body.enabled !== "boolean" || !Number.isSafeInteger(body.intervalMinutes)) {
      return res.status(400).json({ error: "Background protection requires an enabled state and whole-minute interval." });
    }
    try {
      backgroundProtection.configure(session.policyAccountKey, body.enabled, Number(body.intervalMinutes));
      res.setHeader("Cache-Control", "no-store");
      res.json(backgroundProtection.status(session.policyAccountKey));
    } catch (error) {
      res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
    }
  });

  app.get("/api/accounts/:id/scan-history", (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    try {
      res.setHeader("Cache-Control", "no-store");
      res.json({
        persistent: defaultScanStateRepository.persistent,
        history: publicScanHistory(session),
      });
    } catch (error) {
      res.status(500).json({ error: `Protected scan history could not be read: ${error instanceof Error ? error.message : String(error)}` });
    }
  });

  app.get("/api/accounts/:id/scan/resume/:scanId", createResumeScanStreamHandler({ community }));
  app.get("/api/accounts/:id/scan/:type", createScanStreamHandler({ community }));

  app.post("/api/accounts/:id/scan/stop", (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    const worker = session.activeScanWorker;
    if (!worker) return res.json({ stopped: true, active: false });
    requestActiveScanStop(session.id);
    try { worker.postMessage({ type: "cancel" }); } catch {}
    const hardStop = setTimeout(() => { void worker.terminate(); }, 1000);
    hardStop.unref();
    res.json({ stopped: true, active: true });
  });

  app.post("/api/accounts/:id/messages/unblock-sender", (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    let address: string;
    try { address = normalizeSenderAddress((req.body as { address?: unknown }).address); }
    catch (error) { return res.status(400).json({ error: error instanceof Error ? error.message : String(error) }); }

    try {
      sessionStore.mutateAndPersistPersonalPolicy(session, (policy) => policy.unblockSender(address));
      res.json({ blocked: false, persisted: sessionStore.personalPolicyPersistent(), scope: "sender", value: address, accountId: session.id });
    } catch (error) {
      res.status(500).json({ error: `Sender unblock was not saved: ${error instanceof Error ? error.message : String(error)}` });
    }
  });

  app.post("/api/accounts/:id/messages/unblock-domain", (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    let domain: string;
    try { domain = normalizeSenderDomain((req.body as { domain?: unknown }).domain); }
    catch (error) { return res.status(400).json({ error: error instanceof Error ? error.message : String(error) }); }

    try {
      sessionStore.mutateAndPersistPersonalPolicy(session, (policy) => policy.unblockDomain(domain));
      res.json({ blocked: false, persisted: sessionStore.personalPolicyPersistent(), scope: "domain", value: domain, accountId: session.id });
    } catch (error) {
      res.status(500).json({ error: `Domain unblock was not saved: ${error instanceof Error ? error.message : String(error)}` });
    }
  });

  registerPolicyManagementRoutes(app);

  app.use("/api/dev", security.requireProtectedRead());
  app.use("/api/dev", (req: Request, res: Response, next) => {
    if (!security.enforceRouteLimit(req, res, "developer-suite", 5)) return;
    next();
  });

  app.use(inner);
  return app;
}
