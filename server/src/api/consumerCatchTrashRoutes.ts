import type { Express, Request, Response } from "express";
import { sessionStore, type SessionStore } from "./sessionStore.js";
import { defaultConsumerStateRepository } from "./defaultConsumerStateRepository.js";

export interface ConsumerCatchTrashRouteDependencies {
  sessions?: SessionStore;
}

function noStore(res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

function fail(res: Response, error: unknown, status = 400): void {
  noStore(res);
  res.status(status).json({ error: error instanceof Error ? error.message : String(error) });
}

function sessionFor(sessions: SessionStore, req: Request, res: Response) {
  const session = sessions.get(req.params.id!);
  if (!session) {
    fail(res, new Error("Unknown connected mailbox."), 404);
    return null;
  }
  return session;
}

function address(value: unknown): string | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value !== "string") throw new Error("Catch & Trash sender address is invalid.");
  const normalized = value.trim().toLowerCase();
  if (normalized.length < 3 || normalized.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) {
    throw new Error("Catch & Trash sender address is invalid.");
  }
  return normalized;
}

function domain(value: unknown): string | null {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value !== "string") throw new Error("Catch & Trash sender domain is invalid.");
  const normalized = value.trim().toLowerCase().replace(/^@/, "");
  if (normalized.length < 1 || normalized.length > 253 || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(normalized)) {
    throw new Error("Catch & Trash sender domain is invalid.");
  }
  return normalized;
}

function publicSnapshot(session: NonNullable<ReturnType<SessionStore["get"]>>) {
  const policy = session.personalPolicy.snapshot();
  return {
    senders: [...(policy.catchTrashSenders ?? [])],
    domains: [...(policy.catchTrashDomains ?? [])],
    note: "Catch & Trash is a separate personal cleanup rule. It does not report the sender as a scam and does not alter the ordinary Block Sender/Domain lists.",
  };
}

export function registerConsumerCatchTrashRoutes(
  app: Express,
  dependencies: ConsumerCatchTrashRouteDependencies = {},
): void {
  const sessions = dependencies.sessions ?? sessionStore;

  app.get("/api/consumer/v1/accounts/:id/catch-trash", (req, res) => {
    const session = sessionFor(sessions, req, res);
    if (!session) return;
    noStore(res);
    res.json(publicSnapshot(session));
  });

  app.post("/api/consumer/v1/accounts/:id/catch-trash", (req, res) => {
    const session = sessionFor(sessions, req, res);
    if (!session) return;
    try {
      const body = req.body as Record<string, unknown>;
      if (body.confirmation !== "ENABLE CATCH & TRASH") {
        throw new Error("Type ENABLE CATCH & TRASH to confirm this future-mail cleanup rule.");
      }
      const senderAddress = address(body.senderAddress);
      const senderDomain = domain(body.senderDomain);
      if (!senderAddress && !senderDomain) throw new Error("Choose an exact sender address or domain before enabling Catch & Trash.");
      sessions.mutateAndPersistPersonalPolicy(session, (policy) => {
        if (senderAddress) policy.catchTrashSender(senderAddress);
        if (senderDomain) policy.catchTrashDomain(senderDomain);
      });
      defaultConsumerStateRepository.appendActivity(session.policyAccountKey, {
        kind: "settings",
        severity: "info",
        provider: session.config.provider,
        title: "Catch & Trash enabled",
        detail: "Future matching mail will be moved to Trash by your explicit cleanup rule. The sender was not reported to Community or Family Shield.",
        reasonCodes: ["CATCH_TRASH_ENABLED"],
        undo: null,
      });
      noStore(res);
      res.status(201).json(publicSnapshot(session));
    } catch (error) { fail(res, error); }
  });

  app.delete("/api/consumer/v1/accounts/:id/catch-trash", (req, res) => {
    const session = sessionFor(sessions, req, res);
    if (!session) return;
    try {
      const body = req.body as Record<string, unknown>;
      const senderAddress = address(body.senderAddress);
      const senderDomain = domain(body.senderDomain);
      if (!senderAddress && !senderDomain) throw new Error("Choose the Catch & Trash sender or domain to remove.");
      sessions.mutateAndPersistPersonalPolicy(session, (policy) => {
        if (senderAddress) policy.removeCatchTrashSender(senderAddress);
        if (senderDomain) policy.removeCatchTrashDomain(senderDomain);
      });
      defaultConsumerStateRepository.appendActivity(session.policyAccountKey, {
        kind: "settings",
        severity: "info",
        provider: session.config.provider,
        title: "Catch & Trash disabled",
        detail: "The selected future-mail cleanup rule was removed. Ordinary personal block rules were left unchanged.",
        reasonCodes: ["CATCH_TRASH_DISABLED"],
        undo: null,
      });
      noStore(res);
      res.json(publicSnapshot(session));
    } catch (error) { fail(res, error); }
  });
}
