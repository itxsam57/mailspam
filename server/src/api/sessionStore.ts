import { createHash, randomUUID } from "node:crypto";
import type { Worker } from "node:worker_threads";
import type { NormalizedFolder } from "../canonical/envelope.js";
import type { CommunityReportContext } from "../community/types.js";
import { InMemoryPersonalPolicyStore } from "../engine/layers/personalRules.js";
import type { CredentialReference, CredentialVault } from "../security/credentialVault.js";
import { createCredentialVault } from "../security/credentialVaultFactory.js";
import {
  materializeAdapterConfig,
  releaseMemorySecrets,
  secureAdapterConfig,
  secureAdapterConfigInMemory,
  type SecureAdapterConfig,
} from "../security/secureAdapterConfig.js";
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
  normalizedFolder: NormalizedFolder;
  communityReport: CommunityReportContext;
  createdAt: number;
}

export interface AccountSession {
  id: string;
  provider: string;
  label: string;
  /** Provider configuration with secret handles, never the raw runtime AdapterConfig. */
  config: SecureAdapterConfig;
  activeScanWorker: Worker | null;
  personalPolicy: InMemoryPersonalPolicyStore;
  policyAccountKey: string;
  vaultReferences: CredentialReference[];
  unsubscribeActions: Map<string, RegisteredUnsubscribeAction>;
  reviewActions: Map<string, RegisteredReviewAction>;
}

const MAX_SCAN_ACTIONS = 5_000;
const ACTION_TTL_MS = 30 * 60 * 1_000;

function senderDomain(address: string | null): string | null {
  if (!address) return null;
  const separator = address.lastIndexOf("@");
  return separator > 0 && separator < address.length - 1
    ? address.slice(separator + 1).toLowerCase()
    : null;
}

function credentialReferenceKey(reference: CredentialReference): string {
  return `${reference.kind}:${reference.id}`;
}

export class SessionStore {
  private sessions = new Map<string, AccountSession>();
  private policyStores = new Map<string, InMemoryPersonalPolicyStore>();
  private vaultReferenceCounts = new Map<string, number>();

  constructor(
    private readonly policyRepository: PersonalPolicyRepository = new EncryptedFilePolicyRepository(),
    private readonly credentialVault: CredentialVault = createCredentialVault(),
  ) {}

  /**
   * Memory-only session creation retained for deterministic tests and platforms
   * without an implemented native persistent vault. Raw AdapterConfig secrets
   * are immediately converted into handles and are not stored as session.config.
   */
  create(provider: string, label: string, config: AdapterConfig): AccountSession {
    const secured = secureAdapterConfigInMemory(config);
    return this.createFromSecured(provider, label, secured.config, policyAccountKey(config), secured.vaultReferences);
  }

  /**
   * Production connection path. A native vault that advertises availability is
   * authoritative: write failure aborts session creation rather than falling
   * back to plaintext or long-lived raw AdapterConfig storage.
   */
  async createSecured(provider: string, label: string, config: AdapterConfig): Promise<AccountSession> {
    const accountKey = policyAccountKey(config);
    const secured = await secureAdapterConfig(config, this.credentialVault);
    try {
      return this.createFromSecured(provider, label, secured.config, accountKey, secured.vaultReferences);
    } catch (error) {
      // If session initialization fails after a new vault write, clean only
      // references not already owned by another active session. Never delete a
      // shared credential out from underneath a working session.
      try {
        for (const reference of secured.vaultReferences) {
          if ((this.vaultReferenceCounts.get(credentialReferenceKey(reference)) ?? 0) === 0) {
            await this.credentialVault.delete(reference);
          }
        }
      } catch {
        throw new Error("Account session initialization failed and protected credential cleanup also failed.");
      }
      throw error;
    }
  }

  async materializeConfig(session: AccountSession): Promise<AdapterConfig> {
    return materializeAdapterConfig(session.config, this.credentialVault);
  }

  private createFromSecured(
    provider: string,
    label: string,
    config: SecureAdapterConfig,
    accountKey: string,
    vaultReferences: CredentialReference[],
  ): AccountSession {
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
      vaultReferences: vaultReferences.map((reference) => ({ ...reference })),
      unsubscribeActions: new Map(),
      reviewActions: new Map(),
    };
    this.sessions.set(session.id, session);

    for (const reference of session.vaultReferences) {
      const key = credentialReferenceKey(reference);
      this.vaultReferenceCounts.set(key, (this.vaultReferenceCounts.get(key) ?? 0) + 1);
    }
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
    senderBlocked: boolean;
    domainBlocked: boolean;
    canMoveToSpam: boolean;
    canReportSpam: boolean;
    scamAlreadyReported: boolean;
    communityReported: boolean;
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
      normalizedFolder: context.normalizedFolder,
      communityReport: structuredClone(context.communityReport),
      createdAt: Date.now(),
    });
    const canMoveToSpam = context.normalizedFolder !== "spam";
    const alreadyReported = session.personalPolicy.isReportedCampaign(context.communityReport.campaignFingerprint);
    const normalizedSender = context.senderAddress?.toLowerCase() ?? null;
    const normalizedDomain = senderDomain(normalizedSender);
    return {
      token,
      alreadyApproved: session.personalPolicy.isApprovedException(context.exceptionKey),
      senderTrusted: Boolean(normalizedSender && session.personalPolicy.isTrustedSender(normalizedSender)),
      senderBlocked: Boolean(normalizedSender && session.personalPolicy.isBlockedSender(normalizedSender)),
      domainBlocked: Boolean(normalizedDomain && session.personalPolicy.isBlockedDomain(normalizedDomain)),
      canMoveToSpam,
      canReportSpam: canMoveToSpam,
      scamAlreadyReported: alreadyReported,
      communityReported: alreadyReported,
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

    if (session.activeScanWorker) {
      await session.activeScanWorker.terminate();
      session.activeScanWorker = null;
    }

    // Delete native credentials before reporting the last session removed. If
    // the OS refuses deletion, keep the session so the user can retry instead
    // of silently leaving a credential behind while the UI claims success.
    for (const reference of session.vaultReferences) {
      const key = credentialReferenceKey(reference);
      if ((this.vaultReferenceCounts.get(key) ?? 0) === 1) {
        await this.credentialVault.delete(reference);
      }
    }

    this.clearScanActions(session);
    this.sessions.delete(id);
    releaseMemorySecrets(session.config);

    for (const reference of session.vaultReferences) {
      const key = credentialReferenceKey(reference);
      const remaining = (this.vaultReferenceCounts.get(key) ?? 0) - 1;
      if (remaining > 0) this.vaultReferenceCounts.set(key, remaining);
      else this.vaultReferenceCounts.delete(key);
    }
  }
}

export const sessionStore = new SessionStore();