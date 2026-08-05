import { createHash, randomUUID } from "node:crypto";
import type { Worker } from "node:worker_threads";
import { InMemoryPersonalPolicyStore } from "../engine/layers/personalRules.js";
import type { ThreatFeedCache } from "../engine/layers/globalIntelligence.js";
import type { UnsubscribeMethod } from "../workflows/unsubscribe.js";
import type { ScanActionContext } from "../workflows/scanWorkflows.js";
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

export interface RegisteredReviewAction {
  token: string;
  exceptionKey: string;
  senderAddress: string | null;
  providerNativeId: string;
  messageId: string;
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
  reviewActions: Map<string, RegisteredReviewAction>;
}

const emptyFeed: ThreatFeedCache = { getVerifiedEntries: () => [] };
const MAX_SCAN_ACTIONS = 5_000;
const ACTION_TTL_MS = 30 * 60 * 1_000;

export class SessionStore {
  private sessions = new Map<string, AccountSession>();
  private policyStores = new Map<string, InMemoryPersonalPolicyStore>();
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

    const session: AccountSession = {
      id: randomUUID(),
      provider,
      label,
      config,
      activeScanWorker: null,
      personalPolicy,
      policyAccountKey: accountKey,
      unsubscribeActions: new Map(),
      reviewActions: new Map(),
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

  clearScanActions(session: AccountSession): void {
    session.unsubscribeActions.clear();
    session.reviewActions.clear();
  }

  clearUnsubscribeActions(session: AccountSession): void {
    this.clearScanActions(session);
  }

  registerReviewAction(session: AccountSession, context: ScanActionContext): {
    token: string;
    alreadyApproved: boolean;
    senderTrusted: boolean;
  } {
    if (session.reviewActions.size >= MAX_SCAN_ACTIONS) {
      throw new Error("Too many message review actions are registered for this scan.");
    }
    const token = randomUUID();
    session.reviewActions.set(token, {
      token,
      exceptionKey: context.exceptionKey,
      senderAddress: context.senderAddress?.toLowerCase() ?? null,
      providerNativeId: context.providerNativeId,
      messageId: context.messageId,
      createdAt: Date.now(),
    });
    return {
      token,
      alreadyApproved: session.personalPolicy.isApprovedException(context.exceptionKey),
      senderTrusted: Boolean(context.senderAddress && session.personalPolicy.isTrustedSender(context.senderAddress)),
    };
  }

  resolveReviewAction(session: AccountSession, token: unknown): RegisteredReviewAction {
    if (typeof token !== "string" || !/^[0-9a-f-]{36}$/i.test(token)) {
      throw new Error("A valid message review action token is required.");
    }
    const action = session.reviewActions.get(token);
    if (!action) throw new Error("The message review action is unknown or expired. Rescan the mailbox.");
    if (Date.now() - action.createdAt > ACTION_TTL_MS) {
      session.reviewActions.delete(token);
      throw new Error("The message review action expired. Rescan the mailbox.");
    }
    return action;
  }

  registerUnsubscribeAction(
    session: AccountSession,
    method: Exclude<UnsubscribeMethod, "none">,
    target: string,
    providerNativeId: string,
  ): { token: string; actionKey: string; alreadyUnsubscribed: boolean } {
    if (session.unsubscribeActions.size >= MAX_SCAN_ACTIONS) {
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
      alreadyUnsubscribed: session.personalPolicy.isUnsubscribedAction(actionKey),
    };
  }

  resolveUnsubscribeAction(session: AccountSession, token: unknown): RegisteredUnsubscribeAction {
    if (typeof token !== "string" || !/^[0-9a-f-]{36}$/i.test(token)) {
      throw new Error("A valid unsubscribe action token is required.");
    }
    const action = session.unsubscribeActions.get(token);
    if (!action) throw new Error("The unsubscribe action is unknown or expired. Rescan the mailbox.");
    if (Date.now() - action.createdAt > ACTION_TTL_MS) {
      session.unsubscribeActions.delete(token);
      throw new Error("The unsubscribe action expired. Rescan the mailbox.");
    }
    return action;
  }

  markUnsubscribed(session: AccountSession, actionKey: string): void {
    this.mutateAndPersistPersonalPolicy(session, (policy) => policy.rememberUnsubscribed(actionKey));
  }

  get(id: string): AccountSession | undefined { return this.sessions.get(id); }
  list(): AccountSession[] { return [...this.sessions.values()]; }

  async remove(id: string): Promise<void> {
    const session = this.sessions.get(id);
    if (!session) return;
    await session.activeScanWorker?.terminate();
    this.clearScanActions(session);
    this.sessions.delete(id);
  }
}

export const sessionStore = new SessionStore();
