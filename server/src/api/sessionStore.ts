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
}

const emptyFeed: ThreatFeedCache = { getVerifiedEntries: () => [] };

class SessionStore {
  private sessions = new Map<string, AccountSession>();
  readonly personalPolicy = new InMemoryPersonalPolicyStore();
  readonly threatFeed = emptyFeed;

  create(provider: string, label: string, config: AdapterConfig): AccountSession {
    const session: AccountSession = { id: randomUUID(), provider, label, config, activeScanWorker: null };
    this.sessions.set(session.id, session);
    return session;
  }
  get(id: string): AccountSession | undefined { return this.sessions.get(id); }
  list(): AccountSession[] { return [...this.sessions.values()]; }
  async remove(id: string): Promise<void> {
    const session = this.sessions.get(id);
    if (!session) return;
    await session.activeScanWorker?.terminate();
    this.sessions.delete(id);
  }
}
export const sessionStore = new SessionStore();
