import type { Express, Request, Response } from "express";
import type { PersonalPolicySnapshot } from "../engine/layers/personalRules.js";
import { isMessageExceptionKey } from "../workflows/messageReview.js";
import {
  normalizeSenderAddress,
  normalizeSenderDomain,
} from "../workflows/blockAndCleanup.js";
import { sessionStore } from "./sessionStore.js";

export const PERSONAL_POLICY_EXPORT_SCHEMA = "email-shield-personal-policy" as const;
export const PERSONAL_POLICY_EXPORT_VERSION = 1 as const;
export const PERSONAL_POLICY_RESET_CONFIRMATION = "RESET PERSONAL POLICY" as const;

export const PERSONAL_POLICY_CATEGORIES = [
  "blockedSenders",
  "blockedDomains",
  "trustedSenders",
  "approvedExceptions",
  "unsubscribedActions",
  "reportedCampaigns",
] as const;

export type PersonalPolicyCategory = typeof PERSONAL_POLICY_CATEGORIES[number];

export interface PersonalPolicyExportDocument {
  schema: typeof PERSONAL_POLICY_EXPORT_SCHEMA;
  version: typeof PERSONAL_POLICY_EXPORT_VERSION;
  policy: PersonalPolicySnapshot;
}

const MAX_ITEMS_PER_CATEGORY = 10_000;
const MAX_BULK_REVOKE_ITEMS = 500;
const HASH_64 = /^[a-f0-9]{64}$/;

function ownKeys(value: object): string[] {
  return Object.keys(value).sort();
}

function sameKeys(actual: string[], expected: readonly string[]): boolean {
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function requireObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function normalizeHash(value: string, label: string): string {
  const normalized = value.trim().toLowerCase();
  if (!HASH_64.test(normalized)) throw new Error(`${label} is invalid.`);
  return normalized;
}

export function normalizePersonalPolicyValue(category: PersonalPolicyCategory, input: unknown): string {
  if (typeof input !== "string") throw new Error(`Policy value for ${category} must be a string.`);
  if (input.length > 512) throw new Error(`Policy value for ${category} is too long.`);

  switch (category) {
    case "blockedSenders":
    case "trustedSenders":
      return normalizeSenderAddress(input);
    case "blockedDomains":
      return normalizeSenderDomain(input);
    case "approvedExceptions": {
      const value = input.trim().toLowerCase();
      if (isMessageExceptionKey(value)) return value;
      return normalizeSenderAddress(value);
    }
    case "unsubscribedActions":
      return normalizeHash(input, "Unsubscribe record");
    case "reportedCampaigns":
      return normalizeHash(input, "Reported campaign fingerprint");
  }
}

function normalizeCategoryList(category: PersonalPolicyCategory, input: unknown): string[] {
  if (!Array.isArray(input)) throw new Error(`${category} must be an array.`);
  if (input.length > MAX_ITEMS_PER_CATEGORY) throw new Error(`${category} exceeds the local policy limit.`);

  const output: string[] = [];
  const seen = new Set<string>();
  for (const item of input) {
    const normalized = normalizePersonalPolicyValue(category, item);
    if (!seen.has(normalized)) {
      seen.add(normalized);
      output.push(normalized);
    }
  }
  return output;
}

export function parsePersonalPolicyImportDocument(input: unknown): PersonalPolicySnapshot {
  const document = requireObject(input, "Policy import document");
  if (!sameKeys(ownKeys(document), ["schema", "version", "policy"])) {
    throw new Error("Policy import document contains missing or unsupported fields.");
  }
  if (document.schema !== PERSONAL_POLICY_EXPORT_SCHEMA || document.version !== PERSONAL_POLICY_EXPORT_VERSION) {
    throw new Error("Unsupported Email Shield policy backup format.");
  }

  const policy = requireObject(document.policy, "Policy backup payload");
  if (!sameKeys(ownKeys(policy), PERSONAL_POLICY_CATEGORIES)) {
    throw new Error("Policy backup payload contains missing or unsupported fields.");
  }

  return {
    blockedSenders: normalizeCategoryList("blockedSenders", policy.blockedSenders),
    blockedDomains: normalizeCategoryList("blockedDomains", policy.blockedDomains),
    trustedSenders: normalizeCategoryList("trustedSenders", policy.trustedSenders),
    approvedExceptions: normalizeCategoryList("approvedExceptions", policy.approvedExceptions),
    unsubscribedActions: normalizeCategoryList("unsubscribedActions", policy.unsubscribedActions),
    reportedCampaigns: normalizeCategoryList("reportedCampaigns", policy.reportedCampaigns),
  };
}

function cloneSnapshot(snapshot: PersonalPolicySnapshot): PersonalPolicySnapshot {
  return {
    blockedSenders: [...snapshot.blockedSenders],
    blockedDomains: [...snapshot.blockedDomains],
    trustedSenders: [...snapshot.trustedSenders],
    approvedExceptions: [...snapshot.approvedExceptions],
    unsubscribedActions: [...snapshot.unsubscribedActions],
    reportedCampaigns: [...snapshot.reportedCampaigns],
  };
}

export function mergePersonalPolicySnapshots(
  current: PersonalPolicySnapshot,
  incoming: PersonalPolicySnapshot,
): PersonalPolicySnapshot {
  const result = cloneSnapshot(current);
  for (const category of PERSONAL_POLICY_CATEGORIES) {
    result[category] = [...new Set([...result[category], ...incoming[category]])];
  }
  return result;
}

function policyCounts(snapshot: PersonalPolicySnapshot): Record<PersonalPolicyCategory, number> {
  return {
    blockedSenders: snapshot.blockedSenders.length,
    blockedDomains: snapshot.blockedDomains.length,
    trustedSenders: snapshot.trustedSenders.length,
    approvedExceptions: snapshot.approvedExceptions.length,
    unsubscribedActions: snapshot.unsubscribedActions.length,
    reportedCampaigns: snapshot.reportedCampaigns.length,
  };
}

function categoryFromUnknown(value: unknown): PersonalPolicyCategory {
  if (typeof value !== "string" || !(PERSONAL_POLICY_CATEGORIES as readonly string[]).includes(value)) {
    throw new Error("A valid personal-policy category is required.");
  }
  return value as PersonalPolicyCategory;
}

function removeOne(snapshot: PersonalPolicySnapshot, category: PersonalPolicyCategory, value: string): void {
  switch (category) {
    case "blockedSenders": snapshot.blockedSenders = snapshot.blockedSenders.filter((item) => item !== value); break;
    case "blockedDomains": snapshot.blockedDomains = snapshot.blockedDomains.filter((item) => item !== value); break;
    case "trustedSenders": snapshot.trustedSenders = snapshot.trustedSenders.filter((item) => item !== value); break;
    case "approvedExceptions": snapshot.approvedExceptions = snapshot.approvedExceptions.filter((item) => item !== value); break;
    case "unsubscribedActions": snapshot.unsubscribedActions = snapshot.unsubscribedActions.filter((item) => item !== value); break;
    case "reportedCampaigns": snapshot.reportedCampaigns = snapshot.reportedCampaigns.filter((item) => item !== value); break;
  }
}

function noStore(res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function accountSession(req: Request, res: Response) {
  const session = sessionStore.get(req.params.id!);
  if (!session) {
    res.status(404).json({ error: "Unknown account" });
    return null;
  }
  return session;
}

function mutationResponse(session: NonNullable<ReturnType<typeof sessionStore.get>>) {
  const snapshot = session.personalPolicy.snapshot();
  return {
    success: true,
    accountId: session.id,
    persisted: sessionStore.personalPolicyPersistent(),
    counts: policyCounts(snapshot),
  };
}

function persistReplacement(
  session: NonNullable<ReturnType<typeof sessionStore.get>>,
  replacement: PersonalPolicySnapshot,
): void {
  sessionStore.mutateAndPersistPersonalPolicy(session, (policy) => policy.replace(replacement));
  // Scan action tokens carry presentation state captured before this management
  // mutation. Invalidate them so the browser must rescan before acting again.
  sessionStore.clearScanActions(session);
}

export function registerPolicyManagementRoutes(app: Express): void {
  app.get("/api/accounts/:id/personal-policy/export", (req: Request, res: Response) => {
    const session = accountSession(req, res);
    if (!session) return;
    const document: PersonalPolicyExportDocument = {
      schema: PERSONAL_POLICY_EXPORT_SCHEMA,
      version: PERSONAL_POLICY_EXPORT_VERSION,
      policy: cloneSnapshot(session.personalPolicy.snapshot()),
    };
    noStore(res);
    res.setHeader("Content-Disposition", 'attachment; filename="email-shield-personal-policy.json"');
    res.type("application/json").send(JSON.stringify(document));
  });

  app.post("/api/accounts/:id/personal-policy/import", (req: Request, res: Response) => {
    const session = accountSession(req, res);
    if (!session) return;
    const body = requireObject(req.body, "Policy import request");
    if (!sameKeys(ownKeys(body), ["mode", "document"])) {
      return res.status(400).json({ error: "Policy import request contains missing or unsupported fields." });
    }
    if (body.mode !== "merge" && body.mode !== "replace") {
      return res.status(400).json({ error: "Policy import mode must be merge or replace." });
    }

    try {
      const imported = parsePersonalPolicyImportDocument(body.document);
      const replacement = body.mode === "merge"
        ? mergePersonalPolicySnapshots(session.personalPolicy.snapshot(), imported)
        : imported;
      persistReplacement(session, replacement);
      noStore(res);
      res.json({ ...mutationResponse(session), mode: body.mode });
    } catch (error) {
      res.status(400).json({ error: `Policy import was rejected: ${errorMessage(error)}` });
    }
  });

  app.post("/api/accounts/:id/personal-policy/revoke", (req: Request, res: Response) => {
    const session = accountSession(req, res);
    if (!session) return;
    try {
      const body = requireObject(req.body, "Policy revoke request");
      if (!sameKeys(ownKeys(body), ["category", "value"])) throw new Error("Policy revoke request contains missing or unsupported fields.");
      const category = categoryFromUnknown(body.category);
      const value = normalizePersonalPolicyValue(category, body.value);
      const replacement = session.personalPolicy.snapshot();
      removeOne(replacement, category, value);
      persistReplacement(session, replacement);
      res.json({ ...mutationResponse(session), revoked: 1, category, value });
    } catch (error) {
      res.status(400).json({ error: errorMessage(error) });
    }
  });

  app.post("/api/accounts/:id/personal-policy/bulk-revoke", (req: Request, res: Response) => {
    const session = accountSession(req, res);
    if (!session) return;
    try {
      const body = requireObject(req.body, "Bulk policy revoke request");
      if (!sameKeys(ownKeys(body), ["items"]) || !Array.isArray(body.items)) {
        throw new Error("Bulk policy revoke request must contain only an items array.");
      }
      if (!body.items.length || body.items.length > MAX_BULK_REVOKE_ITEMS) {
        throw new Error(`Bulk policy revoke must contain between 1 and ${MAX_BULK_REVOKE_ITEMS} items.`);
      }

      const normalized = new Map<string, { category: PersonalPolicyCategory; value: string }>();
      for (const raw of body.items) {
        const item = requireObject(raw, "Bulk policy item");
        if (!sameKeys(ownKeys(item), ["category", "value"])) throw new Error("Bulk policy item contains missing or unsupported fields.");
        const category = categoryFromUnknown(item.category);
        const value = normalizePersonalPolicyValue(category, item.value);
        normalized.set(`${category}\0${value}`, { category, value });
      }

      const replacement = session.personalPolicy.snapshot();
      for (const item of normalized.values()) removeOne(replacement, item.category, item.value);
      persistReplacement(session, replacement);
      res.json({ ...mutationResponse(session), revoked: normalized.size });
    } catch (error) {
      res.status(400).json({ error: errorMessage(error) });
    }
  });

  app.post("/api/accounts/:id/personal-policy/clear-category", (req: Request, res: Response) => {
    const session = accountSession(req, res);
    if (!session) return;
    try {
      const body = requireObject(req.body, "Policy category clear request");
      if (!sameKeys(ownKeys(body), ["category", "confirmation"])) throw new Error("Policy category clear request contains missing or unsupported fields.");
      const category = categoryFromUnknown(body.category);
      if (body.confirmation !== category) throw new Error("Policy category clear confirmation did not match the selected category.");
      const replacement = session.personalPolicy.snapshot();
      replacement[category] = [];
      persistReplacement(session, replacement);
      res.json({ ...mutationResponse(session), clearedCategory: category });
    } catch (error) {
      res.status(400).json({ error: errorMessage(error) });
    }
  });

  app.post("/api/accounts/:id/personal-policy/reset", (req: Request, res: Response) => {
    const session = accountSession(req, res);
    if (!session) return;
    try {
      const body = requireObject(req.body, "Policy reset request");
      if (!sameKeys(ownKeys(body), ["confirmation"]) || body.confirmation !== PERSONAL_POLICY_RESET_CONFIRMATION) {
        throw new Error(`Reset requires the exact confirmation phrase: ${PERSONAL_POLICY_RESET_CONFIRMATION}`);
      }
      const replacement: PersonalPolicySnapshot = {
        blockedSenders: [],
        blockedDomains: [],
        trustedSenders: [],
        approvedExceptions: [],
        unsubscribedActions: [],
        reportedCampaigns: [],
      };
      persistReplacement(session, replacement);
      res.json({ ...mutationResponse(session), reset: true });
    } catch (error) {
      res.status(400).json({ error: errorMessage(error) });
    }
  });
}
