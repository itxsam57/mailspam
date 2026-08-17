import { createHash, randomUUID } from "node:crypto";
import type { Worker } from "node:worker_threads";
import type { NormalizedFolder } from "../canonical/envelope.js";
import type { CommunityReportContext } from "../community/types.js";
import { InMemoryPersonalPolicyStore } from "../engine/layers/personalRules.js";
import type { CredentialReference, CredentialVault } from "../security/credentialVault.js";
import { createCredentialVault } from "../security/credentialVaultFactory.js";
import {
  providerCredentialRevoker,
  type ProviderCredentialRevoker,
} from "../security/providerCredentialRevocation.js";
import {
  materializeAdapterConfig,
  releaseMemorySecrets,
  secureAdapterConfig,
  secureAdapterConfigInMemory,
  type SecureAdapterConfig,
  type SecretHandle,
} from "../security/secureAdapterConfig.js";
import type { UnsubscribeMethod } from "../workflows/unsubscribe.js";
import type { ScanActionContext, ScanCounters } from "../workflows/scanWorkflows.js";
import type { AdapterConfig } from "./adapterConfig.js";
import { defaultPersonalPolicyRepository } from "./defaultPolicyRepository.js";
import {
  noLiveConnectionPersistence,
  policyAccountKeyFromPersistentConnection,
  secureConfigFromPersistentConnection,
  type LiveConnectionPersistence,
} from "./liveConnectionPersistence.js";
import {
  InMemoryPolicyRepository,
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
  claimedOperations: Set<ReviewActionOperation>;
}

export type ReviewActionOperation = "mark_safe" | "trust_sender" | "report_scam" | "trash" | "report_spam";

type SessionOwnership = "candidate" | "canonical" | "superseded";

export class ReviewActionConflictError extends Error {
  constructor() {
    super("This message action was already used in another tab or request. Rescan to obtain a fresh action.");
    this.name = "ReviewActionConflictError";
  }
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
  closing: boolean;
  unsubscribeActions: Map<string, RegisteredUnsubscribeAction>;
  reviewActions: Map<string, RegisteredReviewAction>;
}

const MAX_SCAN_ACTIONS = 5_000;
const ACTION_TTL_MS = 30 * 60 * 1_000;
const MAX_WORKSPACE_CARDS = 200;
const MAX_WORKSPACE_DIAGNOSTICS = 500;

export interface WorkspaceScanPresentation {
  scanId: string;
  type: string;
  status: "running" | "completed" | "failed" | "stopped";
  updatedAt: number;
  counters: ScanCounters;
  suspiciousCards: unknown[];
  diagnosticSummaries: unknown[];
}

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

function handleReference(handle: SecretHandle | undefined): CredentialReference[] {
  return handle?.storage === "vault" ? [{ ...handle.reference }] : [];
}

function secureConfigReferences(config: SecureAdapterConfig): CredentialReference[] {
  if (config.mode !== "live") return [];
  switch (config.provider) {
    case "gmail":
      return [
        ...handleReference(config.credentials.refreshToken),
        ...handleReference(config.credentials.clientSecret),
      ];
    case "outlook":
      return [
        ...handleReference(config.credentials.refreshToken),
        ...handleReference(config.credentials.clientSecret),
      ];
    case "icloud":
    case "yahoo":
    case "imap":
      return handleReference(config.credentials.appPassword);
  }
}

export class SessionStore {
  private sessions = new Map<string, AccountSession>();
  private sessionOwnership = new Map<string, SessionOwnership>();
  private policyStores = new Map<string, InMemoryPersonalPolicyStore>();
  private vaultReferenceCounts = new Map<string, number>();
  private vaultLifecycleTail: Promise<void> = Promise.resolve();
  private selectedWorkspaceSessionId: string | null = null;
  private workspacePresentations = new Map<string, WorkspaceScanPresentation>();
  private liveConnectionPersistence: LiveConnectionPersistence = noLiveConnectionPersistence;
  private persistentLiveConnectionsRequired = false;

  constructor(
    private readonly policyRepository: PersonalPolicyRepository = new InMemoryPolicyRepository(),
    private readonly credentialVault: CredentialVault = createCredentialVault(),
    private readonly credentialRevoker: ProviderCredentialRevoker = providerCredentialRevoker,
  ) {}

  personalPolicyPersistent(): boolean {
    return this.policyRepository.persistent;
  }

  liveConnectionsPersistent(): boolean {
    return this.liveConnectionPersistence.persistent;
  }

  /**
   * Runtime startup injects the encrypted connection registry after the native
   * credential vault has initialized. Consumer live connections are then
   * required to be restart-restorable instead of silently degrading to memory.
   */
  configureLiveConnectionPersistence(
    persistence: LiveConnectionPersistence,
    options: { required?: boolean } = {},
  ): void {
    if (this.sessions.size !== 0) {
      throw new Error("Live connection persistence must be configured before mailbox sessions are created or restored.");
    }
    this.liveConnectionPersistence = persistence;
    this.persistentLiveConnectionsRequired = options.required === true;
    if (this.persistentLiveConnectionsRequired && !persistence.persistent) {
      // Startup may still proceed so users can use local Scam Check. Any new
      // live mailbox connection will fail closed with a specific message.
      return;
    }
  }

  /**
   * Restore only encrypted metadata + OS-vault handles. No provider secret is
   * materialized here, and the provider is contacted only when protection runs.
   */
  restoreLiveConnections(): AccountSession[] {
    const restored: AccountSession[] = [];
    for (const connection of this.liveConnectionPersistence.list()) {
      const accountKey = policyAccountKeyFromPersistentConnection(connection);
      if (this.canonicalForPolicyAccountKey(accountKey)) continue;
      const config = secureConfigFromPersistentConnection(connection);
      const session = this.createFromSecured(
        connection.provider,
        connection.label,
        config,
        accountKey,
        secureConfigReferences(config),
      );
      this.promoteCanonical(session);
      restored.push(session);
    }
    return restored;
  }

  create(provider: string, label: string, config: AdapterConfig): AccountSession {
    const secured = secureAdapterConfigInMemory(config);
    const session = this.createFromSecured(
      provider,
      label,
      secured.config,
      policyAccountKey(config),
      secured.vaultReferences,
    );
    this.promoteCanonical(session);
    return session;
  }

  /**
   * Production connection path. A native vault that advertises availability is
   * authoritative: write failure aborts session creation rather than falling
   * back to plaintext or long-lived raw AdapterConfig storage. When production
   * runtime persistence is required, connection-registry failure also aborts.
   */
  async createSecured(provider: string, label: string, config: AdapterConfig): Promise<AccountSession> {
    return this.withVaultLifecycle(() => this.createSecuredWithinLifecycle(provider, label, config));
  }

  /**
   * Provider validation that must not race with a final-account revocation uses
   * the same serialized lifecycle transaction as vault write/session creation.
   * Guided Gmail OAuth uses this path so a concurrent Disconnect cannot revoke
   * the grant after validation but before the refresh token is committed.
   */
  async createSecuredValidated(
    provider: string,
    label: string,
    config: AdapterConfig,
    validateProvider: () => Promise<void>,
  ): Promise<AccountSession> {
    return this.withVaultLifecycle(async () => {
      await validateProvider();
      return this.createSecuredWithinLifecycle(provider, label, config);
    });
  }

  async materializeConfig(session: AccountSession): Promise<AdapterConfig> {
    return materializeAdapterConfig(session.config, this.credentialVault);
  }

  private async createSecuredWithinLifecycle(
    provider: string,
    label: string,
    config: AdapterConfig,
  ): Promise<AccountSession> {
    const isLive = config.mode === "live";
    if (isLive && this.persistentLiveConnectionsRequired && !this.liveConnectionPersistence.persistent) {
      throw new Error("Persistent live mailbox protection is unavailable because the native credential vault/connection registry is not durable on this device.");
    }

    const accountKey = policyAccountKey(config);
    // Same-account overlap is intentional during credential rotation/reconnect.
    // A replacement remains an ineligible candidate until both protected
    // credential storage and the newest encrypted persistent descriptor commit.

    const secured = await secureAdapterConfig(config, this.credentialVault);
    let session: AccountSession | null = null;
    try {
      session = this.createFromSecured(provider, label, secured.config, accountKey, secured.vaultReferences);
      if (isLive) this.liveConnectionPersistence.remember(session);
      this.promoteCanonical(session);
      return session;
    } catch (error) {
      if (session) this.rollbackCreatedSession(session);
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

  private rollbackCreatedSession(session: AccountSession): void {
    this.discardScanActions(session);
    this.workspacePresentations.delete(session.id);
    if (this.selectedWorkspaceSessionId === session.id) this.selectedWorkspaceSessionId = null;
    this.sessions.delete(session.id);
    this.sessionOwnership.delete(session.id);
    releaseMemorySecrets(session.config);
    for (const reference of session.vaultReferences) {
      const key = credentialReferenceKey(reference);
      const remaining = (this.vaultReferenceCounts.get(key) ?? 0) - 1;
      if (remaining > 0) this.vaultReferenceCounts.set(key, remaining);
      else this.vaultReferenceCounts.delete(key);
    }
  }

  private async withVaultLifecycle<T>(operation: () => Promise<T>): Promise<T> {
    const run = this.vaultLifecycleTail.then(operation, operation);
    this.vaultLifecycleTail = run.then(() => undefined, () => undefined);
    return run;
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
      closing: false,
      unsubscribeActions: new Map(),
      reviewActions: new Map(),
    };
    this.sessions.set(session.id, session);
    this.sessionOwnership.set(session.id, "candidate");

    for (const reference of session.vaultReferences) {
      const key = credentialReferenceKey(reference);
      this.vaultReferenceCounts.set(key, (this.vaultReferenceCounts.get(key) ?? 0) + 1);
    }
    return session;
  }

  private promoteCanonical(session: AccountSession): void {
    if (this.sessions.get(session.id) !== session || session.closing) {
      throw new Error("A disconnected mailbox session cannot become the canonical protection owner.");
    }

    for (const other of this.sessions.values()) {
      if (other.id === session.id || other.policyAccountKey !== session.policyAccountKey) continue;
      if (this.sessionOwnership.get(other.id) === "canonical") {
        this.sessionOwnership.set(other.id, "superseded");
        if (this.selectedWorkspaceSessionId === other.id) this.selectedWorkspaceSessionId = session.id;
      }
    }
    this.sessionOwnership.set(session.id, "canonical");
  }

  private isCanonical(session: AccountSession): boolean {
    return !session.closing && this.sessionOwnership.get(session.id) === "canonical";
  }

  canonicalForPolicyAccountKey(accountKey: string): AccountSession | undefined {
    const matches = [...this.sessions.values()].filter(
      (session) => session.policyAccountKey === accountKey && this.isCanonical(session),
    );
    if (matches.length > 1) {
      throw new Error("Mailbox session ownership is ambiguous; reconnect this mailbox before protection continues.");
    }
    return matches[0];
  }

  getCanonical(id: string): AccountSession | undefined {
    const session = this.get(id);
    return session && this.isCanonical(session) ? session : undefined;
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

  private pruneExpiredScanActions(session: AccountSession): void {
    const cutoff = Date.now() - ACTION_TTL_MS;
    for (const [token, action] of session.unsubscribeActions) {
      if (action.createdAt <= cutoff) session.unsubscribeActions.delete(token);
    }
    for (const [token, action] of session.reviewActions) {
      if (action.createdAt <= cutoff) session.reviewActions.delete(token);
    }
  }

  private discardScanActions(session: AccountSession): void {
    session.unsubscribeActions.clear();
    session.reviewActions.clear();
  }

  /**
   * Scan start/resume housekeeping must not invalidate still-visible action
   * capabilities from the current bounded workspace. Stop/Resume restores those
   * rows, so their opaque actions remain usable until the normal 30-minute TTL.
   * A truly expired capability is pruned here and account disconnect discards all.
   */
  clearScanActions(session: AccountSession): void {
    this.pruneExpiredScanActions(session);
  }

  clearUnsubscribeActions(session: AccountSession): void {
    session.unsubscribeActions.clear();
  }

  selectWorkspaceSession(id: string): void {
    if (!this.getCanonical(id)) throw new Error("The selected account is no longer the active mailbox connection.");
    this.selectedWorkspaceSessionId = id;
  }

  beginWorkspaceScan(session: AccountSession, scanId: string, type: string, counters: ScanCounters): void {
    if (!this.isCanonical(session)) {
      throw new Error("A superseded mailbox connection cannot start new protection work.");
    }
    this.selectedWorkspaceSessionId = session.id;
    this.workspacePresentations.set(session.id, {
      scanId,
      type,
      status: "running",
      updatedAt: Date.now(),
      counters: { ...counters },
      suspiciousCards: [],
      diagnosticSummaries: [],
    });
  }

  rememberWorkspaceProgress(
    session: AccountSession,
    progress: { counters?: unknown; suspiciousCards?: unknown; diagnosticSummaries?: unknown },
  ): void {
    const presentation = this.workspacePresentations.get(session.id);
    if (!presentation) return;
    if (progress.counters && typeof progress.counters === "object") {
      presentation.counters = structuredClone(progress.counters) as ScanCounters;
    }
    const cards = Array.isArray(progress.suspiciousCards) ? structuredClone(progress.suspiciousCards) : [];
    const diagnostics = Array.isArray(progress.diagnosticSummaries) ? structuredClone(progress.diagnosticSummaries) : [];
    presentation.suspiciousCards = [...cards, ...presentation.suspiciousCards].slice(0, MAX_WORKSPACE_CARDS);
    presentation.diagnosticSummaries = [...presentation.diagnosticSummaries, ...diagnostics].slice(-MAX_WORKSPACE_DIAGNOSTICS);
    presentation.updatedAt = Date.now();
  }

  finishWorkspaceScan(session: AccountSession, status: WorkspaceScanPresentation["status"]): void {
    const presentation = this.workspacePresentations.get(session.id);
    if (!presentation) return;
    presentation.status = status;
    presentation.updatedAt = Date.now();
  }

  workspaceSnapshot(): { selectedAccountId: string | null; presentation: WorkspaceScanPresentation | null } {
    const selected = this.selectedWorkspaceSessionId && this.getCanonical(this.selectedWorkspaceSessionId)
      ? this.selectedWorkspaceSessionId
      : null;
    if (!selected) this.selectedWorkspaceSessionId = null;
    return {
      selectedAccountId: selected,
      presentation: selected && this.workspacePresentations.has(selected)
        ? structuredClone(this.workspacePresentations.get(selected)!)
        : null,
    };
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
    this.pruneExpiredScanActions(session);
    if (session.reviewActions.size >= MAX_SCAN_ACTIONS) {
      throw new Error("Too many message review actions are registered for the current bounded action window.");
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
      claimedOperations: new Set(),
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

  /** Atomically reserves one action kind before any asynchronous provider call. */
  claimReviewAction(
    session: AccountSession,
    token: unknown,
    operation: ReviewActionOperation,
  ): RegisteredReviewAction {
    const action = this.resolveReviewAction(session, token);
    if (action.claimedOperations.has(operation)) throw new ReviewActionConflictError();
    action.claimedOperations.add(operation);
    return action;
  }

  /** Release only when no local or provider side effect was committed. */
  releaseReviewAction(action: RegisteredReviewAction, operation: ReviewActionOperation): void {
    action.claimedOperations.delete(operation);
  }

  registerUnsubscribeAction(
    session: AccountSession,
    method: Exclude<UnsubscribeMethod, "none">,
    target: string,
    providerNativeId: string,
  ): { token: string; actionKey: string; alreadyUnsubscribed: boolean } {
    this.pruneExpiredScanActions(session);
    if (session.unsubscribeActions.size >= MAX_SCAN_ACTIONS) {
      throw new Error("Too many unsubscribe actions are registered for the current bounded action window.");
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

  get(id: string): AccountSession | undefined {
    const session = this.sessions.get(id);
    return session?.closing ? undefined : session;
  }

  list(): AccountSession[] {
    return [...this.sessions.values()].filter((session) => this.isCanonical(session));
  }

  async remove(id: string): Promise<void> {
    const session = this.sessions.get(id);
    if (!session || session.closing) return;
    session.closing = true;
    let persistentDescriptorRemoved = false;

    try {
      if (session.activeScanWorker) {
        await session.activeScanWorker.terminate();
        session.activeScanWorker = null;
      }

      await this.withVaultLifecycle(async () => {
        // Ownership is resolved inside the serialized lifecycle. A reconnect may
        // have promoted a replacement while this removal was waiting its turn.
        const removingCanonical = this.sessionOwnership.get(session.id) === "canonical";

        if (removingCanonical && session.config.mode === "live") {
          this.liveConnectionPersistence.remove(session.policyAccountKey);
          persistentDescriptorRemoved = true;
        }

        if (removingCanonical && this.credentialRevoker.requiresRevocation(session.config)) {
          await this.credentialRevoker.revoke(session.config, this.credentialVault);
        }

        for (const reference of session.vaultReferences) {
          const key = credentialReferenceKey(reference);
          if ((this.vaultReferenceCounts.get(key) ?? 0) === 1) {
            await this.credentialVault.delete(reference);
          }
        }

        this.discardScanActions(session);
        this.workspacePresentations.delete(id);
        if (this.selectedWorkspaceSessionId === id) this.selectedWorkspaceSessionId = null;
        this.sessions.delete(id);
        this.sessionOwnership.delete(id);
        releaseMemorySecrets(session.config);

        for (const reference of session.vaultReferences) {
          const key = credentialReferenceKey(reference);
          const remaining = (this.vaultReferenceCounts.get(key) ?? 0) - 1;
          if (remaining > 0) this.vaultReferenceCounts.set(key, remaining);
          else this.vaultReferenceCounts.delete(key);
        }
      });
    } catch (error) {
      session.closing = false;
      if (persistentDescriptorRemoved && session.config.mode === "live") {
        try { this.liveConnectionPersistence.remember(session); }
        catch {
          throw new Error("Account disconnect failed and Email Shield could not restore the encrypted persistent connection descriptor. Reconnect this mailbox before relying on restart protection.");
        }
      }
      throw error;
    }
  }
}

export const sessionStore = new SessionStore(defaultPersonalPolicyRepository);