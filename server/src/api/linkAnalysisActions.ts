import express, { type Express, type NextFunction, type Request, type Response } from "express";
import type { LinkInfo } from "../canonical/envelope.js";
import {
  analyzeLinks,
  destinationAnalysisCoordinator,
  type DestinationAnalysisCoordinator,
} from "../workflows/analyzeLinks.js";
import type { LocalSecurityManager } from "./localSecurity.js";
import { SessionStore, sessionStore, type AccountSession } from "./sessionStore.js";

const LINK_ACTION_TTL_MS = 30 * 60 * 1_000;
const MAX_LINK_ACTIONS_PER_SESSION = 5_000;

interface RegisteredLinkAnalysisAction {
  token: string;
  links: LinkInfo[];
  createdAt: number;
}

export interface LinkAnalysisActionRouteDependencies {
  security: LocalSecurityManager;
  sessions?: SessionStore;
  destinationAnalyzer?: DestinationAnalysisCoordinator;
}

const installedStores = new WeakSet<SessionStore>();
const actionsBySession = new WeakMap<AccountSession, Map<string, RegisteredLinkAnalysisAction>>();

function actionMap(session: AccountSession): Map<string, RegisteredLinkAnalysisAction> {
  let actions = actionsBySession.get(session);
  if (!actions) {
    actions = new Map();
    actionsBySession.set(session, actions);
  }
  return actions;
}

function prune(actions: Map<string, RegisteredLinkAnalysisAction>, now = Date.now()): void {
  const cutoff = now - LINK_ACTION_TTL_MS;
  for (const [token, action] of actions) {
    if (action.createdAt <= cutoff) actions.delete(token);
  }
}

function registerLinks(session: AccountSession, token: string, links: LinkInfo[]): boolean {
  const actions = actionMap(session);
  prune(actions);
  if (!links.length) return false;
  if (actions.size >= MAX_LINK_ACTIONS_PER_SESSION) {
    throw new Error("Too many Analyze Links actions are registered for the current bounded action window.");
  }
  actions.set(token, {
    token,
    links: structuredClone(links),
    createdAt: Date.now(),
  });
  return true;
}

/**
 * The existing opaque review token remains the public capability. This bridge
 * adds only the canonical link snapshot that the scan worker already produced;
 * raw destinations never have to be trusted when they return from JavaScript.
 */
export function installLinkAnalysisActionBridge(store: SessionStore = sessionStore): void {
  if (installedStores.has(store)) return;
  installedStores.add(store);

  const original = store.registerReviewAction.bind(store);
  store.registerReviewAction = ((session, context) => {
    const reviewAction = original(session, context);
    const canAnalyzeLinks = registerLinks(session, reviewAction.token, context.links ?? []);
    return {
      ...reviewAction,
      canAnalyzeLinks,
    };
  }) as SessionStore["registerReviewAction"];
}

export function resolveLinkAnalysisAction(
  store: SessionStore,
  session: AccountSession,
  token: unknown,
): RegisteredLinkAnalysisAction {
  const reviewAction = store.resolveReviewAction(session, token);
  const actions = actionMap(session);
  prune(actions);
  const registered = actions.get(reviewAction.token);
  if (!registered) {
    throw new Error("This scanned message has no current Analyze Links capability. Rescan the mailbox before analyzing its destinations.");
  }
  return {
    token: registered.token,
    links: structuredClone(registered.links),
    createdAt: registered.createdAt,
  };
}

function routeLimit(security: LocalSecurityManager) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!security.enforceRouteLimit(req, res, "analyze-message-links", 30)) return;
    next();
  };
}

function noStore(res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

function tokenBody(body: unknown): unknown {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("Analyze Links requires the opaque scanned-message action token.");
  }
  const value = body as Record<string, unknown>;
  if (Object.keys(value).some((key) => key !== "token")) {
    throw new Error("Analyze Links accepts only the opaque scanned-message action token.");
  }
  return value.token;
}

/**
 * Canonical consumer Analyze Links route. It is registered before the legacy
 * desktop API route, so consumer execution can never accept a browser-supplied
 * envelope or raw destination list as authority.
 */
export function registerLinkAnalysisActionRoutes(
  app: Express,
  dependencies: LinkAnalysisActionRouteDependencies,
): void {
  const sessions = dependencies.sessions ?? sessionStore;
  const analyzer = dependencies.destinationAnalyzer ?? destinationAnalysisCoordinator;
  installLinkAnalysisActionBridge(sessions);

  app.post(
    "/api/accounts/:id/messages/analyze-links",
    dependencies.security.validateLoopbackRequest,
    dependencies.security.securityHeaders,
    dependencies.security.redactResponses(),
    dependencies.security.requireMutation(),
    routeLimit(dependencies.security),
    express.json({ limit: "2kb", strict: true }),
    async (req: Request, res: Response) => {
      const session = sessions.get(req.params.id!);
      if (!session) return res.status(404).json({ error: "Unknown connected mailbox." });

      let token: unknown;
      let action: RegisteredLinkAnalysisAction;
      try {
        token = tokenBody(req.body);
        action = resolveLinkAnalysisAction(sessions, session, token);
      } catch (error) {
        noStore(res);
        return res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
      }

      try {
        const result = await analyzeLinks({ links: action.links }, analyzer);
        noStore(res);
        return res.json({
          ...result,
          accountId: session.id,
          token: action.token,
          analyzedDestinations: result.results.length,
        });
      } catch {
        noStore(res);
        return res.status(502).json({
          error: "Analyze Links could not complete a trusted destination analysis. No destination was treated as safe.",
          accountId: session.id,
          token: action.token,
        });
      }
    },
  );
}
