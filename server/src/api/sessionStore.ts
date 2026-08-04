import { randomUUID } from "node:crypto";
import type { Worker } from "node:worker_threads";
import { InMemoryPersonalPolicyStore } from "../engine/layers/personalRules.js";
import type { ThreatFeedCache } from "../engine/layers/globalIntelligence.js";
import type { AdapterConfig } from "./adapterConfig.js";

export interface AccountSession {
  id: string;
  provider: string;
  label: string;
  config: AdapterConfig;
  activeScanWorker: Worker | null;
  personalPolicy: InMemoryPersonalPolicyStore;
}

const emptyFeed: ThreatFeedCache = { getVerifiedEntries: () => [] };

export class SessionStore {
  private sessions = new Map<string, AccountSession>();
  readonly threatFeed = emptyFeed;

  create(provider: string, label: string, config: AdapterConfig): AccountSession {
    const session: AccountSession = {
      id: randomUUID(),
      provider,
      label,
      config,
      activeScanWorker: null,
      personalPolicy: new InMemoryPersonalPolicyStore(),
    };
    this.sessions.set(session.id, session);
    return session;
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
