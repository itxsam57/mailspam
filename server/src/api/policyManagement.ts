import type { Express, Request, Response } from "express";
import type { PersonalPolicySnapshot } from "../engine/layers/personalRules.js";
import { isMessageExceptionKey } from "../workflows/messageReview.js";
import {
  normalizeSenderAddress,
  normalizeSenderDomain,
} from "../workflows/blockAndCleanup.js";
import { registerProtectionActionRoutes } from "./protectionActions.js";
import { sessionStore } from "./sessionStore.js";

export const PERSONAL_POLICY_EXPORT_SCHEMA = "email-shield-personal-policy" as const;
export const PERSONAL_POLICY_EXPORT_VERSION = 1 as const;
export const PERSONAL_POLICY_RESET_CONFIRMATION = "RESET PERSONAL POLICY" as const;

const LEGACY_PERSONAL_POLICY_CATEGORIES = [
  "blockedSenders",
  "blockedDomains",
  "trustedSenders",
  "approvedExceptions",
  "unsubscribedActions",
  "reportedCampaigns",
] as const;

export const PERSONAL_POLICY_CATEGORIES = [
  "blockedSenders",
  "blockedDomains",
  "catchTrashSenders",
  "catchTrashDomains",
  "trustedSenders",
  "approvedExceptions",
  "unsubscribedActions",
  "reportedCampaigns",
] as const;

export type PersonalPolicyCategory = typeof PERSONAL_POLICY_CATEGORIES[number];

type CompletePersonalPolicySnapshot = Omit<PersonalPolicySnapshot, "catchTrashSenders" | "catchTrashDomains"> & {
  catchTrashSenders: string[];
  catchTrashDomains: string[];
};

export interface PersonalPolicyExportDocument {
  schema: typeof PERSONAL_POLICY_EXPORT_SCHEMA;
  version: typeof PERSONAL_POLICY_EXPORT_VERSION;
  policy: CompletePersonalPolicySnapshot;
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
    case "catchTrashSenders":
    case "trustedSenders":
      return normalizeSenderAddress(input);
    case "blockedDomains":
    case "catchTrashDomains":
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

function completeSnapshot(snapshot: PersonalPolicySnapshot): CompletePersonalPolicySnapshot {
  return {
    blockedSenders: [...snapshot.blockedSenders],
    blockedDomains: [...snapshot.blockedDomains],
    catchTrashSenders: [...(snapshot.catchTrashSenders ?? [])],
    catchTrashDomains: [...(snapshot.catchTrashDomains ?? [])],
    trustedSenders: [...snapshot.trustedSenders],
    approvedExceptions: [...snapshot.approvedExceptions],
    unsubscribedActions: [...snapshot.unsubscribedActions],
    reportedCampaigns: [...snapshot.reportedCampaigns],
  };
}

export function parsePersonalPolicyImportDocument(input: unknown): CompletePersonalPolicySnapshot {
  const document = requireObject(input, "Policy import document");
  if (!sameKeys(ownKeys(document), ["schema", "version", "policy"])) {
    throw new Error("Policy import document contains missing or unsupported fields.");
  }
  if (document.schema !== PERSONAL_POLICY_EXPORT_SCHEMA || document.version !== PERSONAL_POLICY_EXPORT_VERSION) {
    throw new Error("Unsupported Email Shield policy backup format.");
  }

  const policy = requireObject(document.policy, "Policy backup payload");
  const policyKeys = ownKeys(policy);
  const legacy = sameKeys(policyKeys, LEGACY_PERSONAL_POLICY_CATEGORIES);
  const extended = sameKeys(policyKeys, PERSONAL_POLICY_CATEGORIES);
  if (!legacy && !extended) {
    throw new Error("Policy backup payload contains missing or unsupported fields.");
  }

  return {
    blockedSenders: normalizeCategoryList("blockedSenders", policy.blockedSenders),
    blockedDomains: normalizeCategoryList("blockedDomains", policy.blockedDomains),
    catchTrashSenders: extended ? normalizeCategoryList("catchTrashSenders", policy.catchTrashSenders) : [],
    catchTrashDomains: extended ? normalizeCategoryList("catchTrashDomains", policy.catchTrashDomains) : [],
    trustedSenders: normalizeCategoryList("trustedSenders", policy.trustedSenders),
    approvedExceptions: normalizeCategoryList("approvedExceptions", policy.approvedExceptions),
    unsubscribedActions: normalizeCategoryList("unsubscribedActions", policy.unsubscribedActions),
    reportedCampaigns: normalizeCategoryList("reportedCampaigns", policy.reportedCampaigns),
  };
}

function mergePersonalPolicySnapshots(
  current: PersonalPolicySnapshot,
  incoming: CompletePersonalPolicySnapshot,
): CompletePersonalPolicySnapshot {
  const result = completeSnapshot(current);
  for (const category of PERSONAL_POLICY_CATEGORIES) {
    result[category] = [...new Set([...result[category], ...incoming[category]])];
  }
  return result;
}

function policyCounts(snapshot: PersonalPolicySnapshot): Record<PersonalPolicyCategory, number> {
  const complete = completeSnapshot(snapshot);
  return Object.fromEntries(
    PERSONAL_POLICY_CATEGORIES.map((category) => [category, complete[category].length]),
  ) as Record<PersonalPolicyCategory, number>;
}

function categoryFromUnknown(value: unknown): PersonalPolicyCategory {
  if (typeof value !== "string" || !(PERSONAL_POLICY_CATEGORIES as readonly string[]).includes(value)) {
    throw new Error("A valid personal-policy category is required.");
  }
  return value as PersonalPolicyCategory;
}

function removeOne(snapshot: CompletePersonalPolicySnapshot, category: PersonalPolicyCategory, value: string): number {
  const before = snapshot[category].length;
  snapshot[category] = snapshot[category].filter((item) => item !== value);
  return before - snapshot[category].length;
}

function noStore(res: Response): void {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function accountSession(req: Request, res: Response) {
  const session = sessionStore.getCanonical(req.params.id!);
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

function saveOrFail(
  res: Response,
  session: NonNullable<ReturnType<typeof sessionStore.get>>,
  replacement: PersonalPolicySnapshot,
  label: string,
): boolean {
  try {
    persistReplacement(session, replacement);
    return true;
  } catch (error) {
    noStore(res);
    res.status(500).json({ error: `${label} was not saved: ${errorMessage(error)}` });
    return false;
  }
}

export function registerPolicyManagementRoutes(app: Express): void {
  registerProtectionActionRoutes(app);

  app.get("/api/accounts/:id/personal-policy/export", (req: Request, res: Response) => {
    const session = accountSession(req, res);
    if (!session) return;
    const document: PersonalPolicyExportDocument = {
      schema: PERSONAL_POLICY_EXPORT_SCHEMA,
      version: PERSONAL_POLICY_EXPORT_VERSION,
      policy: completeSnapshot(session.personalPolicy.snapshot()),
    };
    noStore(res);
    res.setHeader("Content-Disposition", 'attachment; filename="email-shield-personal-policy.json"');
    res.type("application/json").send(JSON.stringify(document));
  });

  app.post("/api/accounts/:id/personal-policy/import", (req: Request, res: Response) => {
    const session = accountSession(req, res);
    if (!session) return;

    let mode: "merge" | "replace";
    let replacement: CompletePersonalPolicySnapshot;
    try {
      const body = requireObject(req.body, "Policy import request");
      if (!sameKeys(ownKeys(body), ["mode", "document"])) {
        throw new Error("Policy import request contains missing or unsupported fields.");
      }
      if (body.mode !== "merge" && body.mode !== "replace") {
        throw new Error("Policy import mode must be merge or replace.");
      }
      mode = body.mode;
      const imported = parsePersonalPolicyImportDocument(body.document);
      replacement = mode === "merge"
        ? mergePersonalPolicySnapshots(session.personalPolicy.snapshot(), imported)
        : imported;
    } catch (error) {
      noStore(res);
      return res.status(400).json({ error: `Policy import was rejected: ${errorMessage(error)}` });
    }

    if (!saveOrFail(res, session, replacement, "Policy import")) return;
    noStore(res);
    res.json({ ...mutationResponse(session), mode });
  });

  app.post("/api/accounts/:id/personal-policy/revoke", (req: Request, res: Response) => {
    const session = accountSession(req, res);
    if (!session) return;

    let category: PersonalPolicyCategory;
    let value: string;
    let replacement: CompletePersonalPolicySnapshot;
    let revoked: number;
    try {
      const body = requireObject(req.body, "Policy revoke request");
      if (!sameKeys(ownKeys(body), ["category", "value"])) throw new Error("Policy revoke request contains missing or unsupported fields.");
      category = categoryFromUnknown(body.category);
      value = normalizePersonalPolicyValue(category, body.value);
      replacement = completeSnapshot(session.personalPolicy.snapshot());
      revoked = removeOne(replacement, category, value);
    } catch (error) {
      noStore(res);
      return res.status(400).json({ error: errorMessage(error) });
    }

    if (!saveOrFail(res, session, replacement, "Policy revoke")) return;
    noStore(res);
    res.json({ ...mutationResponse(session), revoked, category, value });
  });

  app.post("/api/accounts/:id/personal-policy/bulk-revoke", (req: Request, res: Response) => {
    const session = accountSession(req, res);
    if (!session) return;

    let replacement: CompletePersonalPolicySnapshot;
    let revoked = 0;
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

      replacement = completeSnapshot(session.personalPolicy.snapshot());
      for (const item of normalized.values()) revoked += removeOne(replacement, item.category, item.value);
    } catch (error) {
      noStore(res);
      return res.status(400).json({ error: errorMessage(error) });
    }

    if (!saveOrFail(res, session, replacement, "Bulk policy revoke")) return;
    noStore(res);
    res.json({ ...mutationResponse(session), revoked });
  });

  app.post("/api/accounts/:id/personal-policy/clear-category", (req: Request, res: Response) => {
    const session = accountSession(req, res);
    if (!session) return;

    let category: PersonalPolicyCategory;
    let replacement: CompletePersonalPolicySnapshot;
    let removed: number;
    try {
      const body = requireObject(req.body, "Policy category clear request");
      if (!sameKeys(ownKeys(body), ["category", "confirmation"])) throw new Error("Policy category clear request contains missing or unsupported fields.");
      category = categoryFromUnknown(body.category);
      if (body.confirmation !== category) throw new Error("Policy category clear confirmation did not match the selected category.");
      replacement = completeSnapshot(session.personalPolicy.snapshot());
      removed = replacement[category].length;
      replacement[category] = [];
    } catch (error) {
      noStore(res);
      return res.status(400).json({ error: errorMessage(error) });
    }

    if (!saveOrFail(res, session, replacement, "Policy category clear")) return;
    noStore(res);
    res.json({ ...mutationResponse(session), clearedCategory: category, removed });
  });

  app.post("/api/accounts/:id/personal-policy/reset", (req: Request, res: Response) => {
    const session = accountSession(req, res);
    if (!session) return;

    let removed = 0;
    try {
      const body = requireObject(req.body, "Policy reset request");
      if (!sameKeys(ownKeys(body), ["confirmation"]) || body.confirmation !== PERSONAL_POLICY_RESET_CONFIRMATION) {
        throw new Error(`Reset requires the exact confirmation phrase: ${PERSONAL_POLICY_RESET_CONFIRMATION}`);
      }
      const current = completeSnapshot(session.personalPolicy.snapshot());
      removed = PERSONAL_POLICY_CATEGORIES.reduce((sum, category) => sum + current[category].length, 0);
    } catch (error) {
      noStore(res);
      return res.status(400).json({ error: errorMessage(error) });
    }

    const replacement: CompletePersonalPolicySnapshot = {
      blockedSenders: [],
      blockedDomains: [],
      catchTrashSenders: [],
      catchTrashDomains: [],
      trustedSenders: [],
      approvedExceptions: [],
      unsubscribedActions: [],
      reportedCampaigns: [],
    };
    if (!saveOrFail(res, session, replacement, "Policy reset")) return;
    noStore(res);
    res.json({ ...mutationResponse(session), reset: true, removed });
  });
}
