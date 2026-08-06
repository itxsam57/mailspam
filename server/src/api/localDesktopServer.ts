import express from "express";
import type { Request, Response } from "express";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createServer } from "./server.js";
import { localSecurity, type LocalSecurityManager } from "./localSecurity.js";
import type { CommunityNetwork } from "../community/network.js";

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
} = {}) {
  const app = express();
  const security = options.security ?? localSecurity;
  const inner = createServer({ community: options.community });
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
        '<script src="/scan-monitor.js"></script><script src="/unsubscribe-monitor.js"></script></body>',
      );

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

  app.use("/api/dev", security.requireProtectedRead());
  app.use("/api/dev", (req: Request, res: Response, next) => {
    if (!security.enforceRouteLimit(req, res, "developer-suite", 5)) return;
    next();
  });

  app.use(inner);
  return app;
}
