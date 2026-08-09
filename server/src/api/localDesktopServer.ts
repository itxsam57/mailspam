import express from "express";
import type { Request, Response } from "express";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createServer } from "./server.js";
import { localSecurity, type LocalSecurityManager } from "./localSecurity.js";
import { createScanStreamHandler } from "./scanStream.js";
import { sessionStore } from "./sessionStore.js";
import { communityNetwork, type CommunityNetwork } from "../community/network.js";
import { GoogleOAuthFlowManager, GOOGLE_GMAIL_MODIFY_SCOPE } from "../oauth/googleOAuthFlow.js";
import {
  normalizeSenderAddress,
  normalizeSenderDomain,
} from "../workflows/blockAndCleanup.js";

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
  return /^\/[^/]+\/scan\/(?:quick|full|spam)$/.test(path);
}

/**
 * Public desktop entry point. The inner application retains provider and
 * detection behavior; this wrapper supplies the local browser/process trust
 * boundary before any mailbox or developer route can execute.
 */
export function createLocalDesktopServer(options: {
  community?: CommunityNetwork;
  security?: LocalSecurityManager;
  googleOAuth?: GoogleOAuthFlowManager;
} = {}) {
  const app = express();
  const security = options.security ?? localSecurity;
  const community = options.community ?? communityNetwork;
  const googleOAuth = options.googleOAuth ?? new GoogleOAuthFlowManager({
    clientId: process.env.EMAIL_SHIELD_GOOGLE_CLIENT_ID?.trim() ?? "",
    sessionStore,
  });
  const inner = createServer({ community });
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
        '<script src="/scan-monitor.js"></script><script src="/unsubscribe-monitor.js"></script><script src="/gmail-oauth.js"></script></body>',
      );

    // EventSource cannot attach the protected-read CSRF header. Its scan GET is
    // authenticated by the HttpOnly local session and a same-origin Referer.
    // Keep cross-origin referrers suppressed while allowing that browser-native
    // same-origin proof to reach requireScanSource().
    res.setHeader("Referrer-Policy", "same-origin");
    res.setHeader(
      "Content-Security-Policy",
      [
        "default-src 'self'",
        `script-src 'self' 'nonce-${context.cspNonce}'`,
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
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
      res.status(503).json({
        error: error instanceof Error ? error.message : String(error),
      });
    }
  });

  app.get("/api/accounts/oauth/google/status/:flowId", (req: Request, res: Response) => {
    res.setHeader("Cache-Control", "no-store");
    const status = googleOAuth.status(req.params.flowId!);
    res.status(status.status === "error" && status.error.startsWith("Unknown") ? 404 : 200).json(status);
  });

  app.get("/api/accounts/:id/scan/:type", createScanStreamHandler({ community }));

  app.post("/api/accounts/:id/messages/unblock-sender", (req: Request, res: Response) => {
    const session = sessionStore.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown account" });
    let address: string;
    try { address = normalizeSenderAddress((req.body as { address?: unknown }).address); }
    catch (error) { return res.status(400).json({ error: error instanceof Error ? error.message : String(error) }); }

    try {
      sessionStore.mutateAndPersistPersonalPolicy(session, (policy) => policy.unblockSender(address));
      res.json({ blocked: false, persisted: true, scope: "sender", value: address, accountId: session.id });
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
      res.json({ blocked: false, persisted: true, scope: "domain", value: domain, accountId: session.id });
    } catch (error) {
      res.status(500).json({ error: `Domain unblock was not saved: ${error instanceof Error ? error.message : String(error)}` });
    }
  });

  app.use("/api/dev", security.requireProtectedRead());
  app.use("/api/dev", (req: Request, res: Response, next) => {
    if (!security.enforceRouteLimit(req, res, "developer-suite", 5)) return;
    next();
  });

  app.use(inner);
  return app;
}
