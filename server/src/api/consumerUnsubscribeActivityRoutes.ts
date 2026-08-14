import type { Express, Request, Response } from "express";
import { defaultConsumerStateRepository } from "./defaultConsumerStateRepository.js";
import { sessionStore, type SessionStore } from "./sessionStore.js";
import type { ConsumerStateRepository } from "./consumerStatePersistence.js";

export interface ConsumerUnsubscribeActivityDependencies {
  sessions?: SessionStore;
  activity?: Pick<ConsumerStateRepository, "appendActivity">;
}

function noStore(res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

/**
 * Records only the browser/manual handoff that Email Shield can prove happened.
 * The external service page or user's mail client owns final completion, so this
 * route must never mark the encrypted personal policy as unsubscribed.
 */
export function registerConsumerUnsubscribeActivityRoutes(
  app: Express,
  dependencies: ConsumerUnsubscribeActivityDependencies = {},
): void {
  const sessions = dependencies.sessions ?? sessionStore;
  const activity = dependencies.activity ?? defaultConsumerStateRepository;

  app.post("/api/consumer/v1/accounts/:id/unsubscribe-activity", (req: Request, res: Response) => {
    const session = sessions.get(req.params.id!);
    if (!session) return res.status(404).json({ error: "Unknown connected mailbox." });

    let action;
    try { action = sessions.resolveUnsubscribeAction(session, (req.body as { token?: unknown }).token); }
    catch (error) {
      return res.status(400).json({ error: error instanceof Error ? error.message : String(error) });
    }
    if (action.method !== "link_only" && action.method !== "mailto") {
      return res.status(409).json({ error: "Only a manual unsubscribe handoff can be recorded through this route." });
    }

    try {
      const entry = activity.appendActivity(session.policyAccountKey, {
        kind: "unsubscribed",
        severity: "info",
        provider: session.config.provider,
        title: action.method === "link_only" ? "Unsubscribe page opened" : "Unsubscribe email request opened",
        detail: action.method === "link_only"
          ? "Email Shield opened the message-authorized unsubscribe page. Completion is not claimed until the external service confirms it."
          : "Email Shield opened the message-authorized unsubscribe email request. Completion is not claimed because the user must send the request.",
        reasonCodes: [action.method === "link_only" ? "MANUAL_UNSUBSCRIBE_PAGE_OPENED" : "MANUAL_UNSUBSCRIBE_MAIL_OPENED"],
        undo: null,
      });
      noStore(res);
      return res.status(201).json({
        recorded: true,
        activityId: entry.activityId,
        accountId: session.id,
        actionKey: action.actionKey,
        method: action.method,
        completionVerified: false,
      });
    } catch (error) {
      return res.status(500).json({ error: `Manual unsubscribe activity could not be saved: ${error instanceof Error ? error.message : String(error)}` });
    }
  });
}