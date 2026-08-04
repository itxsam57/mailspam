import { createHash, randomUUID } from "node:crypto";
import type { Worker } from "node:worker_threads";
import { InMemoryPersonalPolicyStore } from "../engine/layers/personalRules.js";
import type { ThreatFeedCache } from "../engine/layers/globalIntelligence.js";
import type { UnsubscribeMethod } from "../workflows/unsubscribe.js";
import type { AdapterConfig } from "./adapterConfig.js";
import {
  EncryptedFilePolicyRepository,
  policyAccountKey,
  type PersonalPolicyRepository,
} from "./policyPersistence.js";

export interface RegisteredUnsubscribeAction {
  token: string;
  actionKey: string;
  method: Exclude<UnsubscribeMethod, "none">;
  target: string;
  providerNativeId: string;
  createdAt: number;
}

export interface AccountSession {
  id: string;
  provider: string;
  label: string;
  config: AdapterConfig;
  activeScanWorker: Worker | null;
  personalPolicy: InMemoryPersonalPolicyStore;
  policyAccountKey: string;
  unsubscribeActions: Map<string, RegisteredUnsubscribeAction>;
  unsubscribedActionKeys: Set<string>;
}

const emptyFeed: ThreatFeedCache = { getVerifiedEntries: () => [] };
const MAX_UNSUBSCRIBE_ACTIONS = 5_000;
const UNSUBSCRIBE_ACTION_TTL_MS = 30 * 60 * 1_000;

export class SessionStore {
  private sessions = new Map<string, AccountSession>();
  private policyStores = new Map<string, InMemoryPersonalPolicyStore>();
  private unsubscribeHistories = new Map<string, Set<string>>();
  readonly threatFeed = emptyFeed;

  constructor(private readonly policyRepository: PersonalPolicyRepository = new EncryptedFilePolicyRepository()) {}

  create(provider: string, label: string, config: AdapterConfig): AccountSession {
    const accountKey = policyAccountKey(config);
    let personalPolicy = this.policyStores.get(accountKey);
    if (!personalPolicy) {
      personalPolicy = new InMemoryPersonalPolicyStore();
      personalPolicy.restore(this.policyRepository.load(accountKey));
      this.policyStores.set(accountKey, personalPolicy);
    }

    let unsubscribedActionKeys = this.unsubscribeHistories.get(accountKey);
    if (!unsubscribedActionKeys) {
      unsubscribedActionKeys = new Set<string>();
      this.unsubscribeHistories.set(accountKey, unsubscribedActionKeys);
    }

    const session: AccountSession = {
      id: randomUUID(),
      provider,
      label,
      config,
      activeScanWorker: null,
      personalPolicy,
      policyAccountKey: accountKey,
      unsubscribeActions: new Map(),
      unsubscribedActionKeys,
    };
    this.sessions.set(session.id, session);
    return session;
  }

  persistPersonalPolicy(session: AccountSession): void {
    this.policyRepository.save(session.policyAccountKey, session.personalPolicy.snapshot());
  }

  mutateAndPersistPersonalPolicy(session: AccountSession, mutation: (policy: InMemoryPersonalPolicyStore) => void): void {
    const previous = session.personalPolicy.snapshot();
    mutation(session.personalPolicy);
    try { this.persistPersonalPolicy(session); }
    catch (error) { session.personalPolicy.replace(previous); throw error; }
  }

  clearUnsubscribeActions(session: AccountSession): void {
    session.unsubscribeActions.clear();
  }

  registerUnsubscribeAction(
    session: AccountSession,
    method: Exclude<UnsubscribeMethod, "none">,
    target: string,
    providerNativeId: string,
  ): { token: string; actionKey: string; alreadyUnsubscribed: boolean } {
    if (session.unsubscribeActions.size >= MAX_UNSUBSCRIBE_ACTIONS) {
      throw new Error("Too many unsubscribe actions are registered for this scan.");
    }
    const actionKey = createHash("sha256").update(`${method}\n${target}`).digest("hex");
    const token = randomUUID();
    session.unsubscribeActions.set(token, {
      token,
      actionKey,
      method,
      target,
      providerNativeId,
      createdAt: Date.now(),
    });
    return {
      token,
      actionKey,
      alreadyUnsubscribed: method === "one_click_post" && session.unsubscribedActionKeys.has(actionKey),
    };
  }

  resolveUnsubscribeAction(session: AccountSession, token: unknown): RegisteredUnsubscribeAction {
    if (typeof token !== "string" || !/^[0-9a-f-]{36}$/i.test(token)) {
      throw new Error("A valid unsubscribe action token is required.");
    }
    const action = session.unsubscribeActions.get(token);
    if (!action) throw new Error("The unsubscribe action is unknown or expired. Rescan the mailbox.");
    if (Date.now() - action.createdAt > UNSUBSCRIBE_ACTION_TTL_MS) {
      session.unsubscribeActions.delete(token);
      throw new Error("The unsubscribe action expired. Rescan the mailbox.");
    }
    return action;
  }

  markUnsubscribed(session: AccountSession, actionKey: string): void {
    session.unsubscribedActionKeys.add(actionKey);
  }

  get(id: string): AccountSession | undefined { return this.sessions.get(id); }
  list(): AccountSession[] { return [...this.sessions.values()]; }

  async remove(id: string): Promise<void> {
    const session = this.sessions.get(id);
    if (!session) return;
    await session.activeScanWorker?.terminate();
    session.unsubscribeActions.clear();
    this.sessions.delete(id);
  }
}

export const sessionStore = new SessionStore();
