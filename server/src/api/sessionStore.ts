import { randomUUID } from "node:crypto";
import type { Worker } from "node:worker_threads";
import { InMemoryPersonalPolicyStore } from "../engine/layers/personalRules.js";
import type { ThreatFeedCache } from "../engine/layers/globalIntelligence.js";
import type { AdapterConfig } from "./adapterConfig.js";
import {
  EncryptedFilePolicyRepository,
  policyAccountKey,
  type PersonalPolicyRepository,
} from "./policyPersistence.js";

export interface AccountSession {
  id: string;
  provider: string;
  label: string;
  config: AdapterConfig;
  activeScanWorker: Worker | null;
  personalPolicy: InMemoryPersonalPolicyStore;
  policyAccountKey: string;
}

const emptyFeed: ThreatFeedCache = { getVerifiedEntries: () => [] };

export class SessionStore {
  private sessions = new Map<string, AccountSession>();
  private policyStores = new Map<string, InMemoryPersonalPolicyStore>();
  readonly threatFeed = emptyFeed;

  constructor(
    private readonly policyRepository: PersonalPolicyRepository = new EncryptedFilePolicyRepository(),
  ) {}

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
    };
    this.sessions.set(session.id, session);
    return session;
  }

  persistPersonalPolicy(session: AccountSession): void {
    this.policyRepository.save(session.policyAccountKey, session.personalPolicy.snapshot());
  }

  get(id: string): AccountSession | undefined {
    return this.sessions.get(id);
  }

  list(): AccountSession[] {
    return [...this.sessions.values()];
  }

  async remove(id: string): Promise<void> {
    const session = this.sessions.get(id);
    if (!session) return;
    await session.activeScanWorker?.terminate();
    this.sessions.delete(id);
  }
}

export const sessionStore = new SessionStore();
