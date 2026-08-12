import type {
  BackgroundProtectionExecutor,
  WorkerBackgroundProtectionExecutor,
} from "../api/backgroundProtection.js";
import { BackgroundProtectionRunError } from "../api/backgroundProtection.js";
import type { AccountSession } from "../api/sessionStore.js";
import type { ScanCounters } from "../workflows/scanWorkflows.js";

export interface SummaryProtectionExecutor extends BackgroundProtectionExecutor {
  executeWithSummary(session: AccountSession): Promise<ScanCounters>;
}

/**
 * Shared fail-fast execution gate for scheduled and realtime protection.
 *
 * It intentionally does not queue behind an active scan: realtime triggers
 * remain unacknowledged and scheduled scans keep their existing bounded retry
 * policy instead of growing a hidden in-memory work queue.
 */
export class SerialProtectionExecutor implements SummaryProtectionExecutor {
  #activeAccountKey: string | null = null;

  constructor(
    private readonly inner: Pick<WorkerBackgroundProtectionExecutor, "executeWithSummary">,
  ) {}

  get activeAccountKey(): string | null {
    return this.#activeAccountKey;
  }

  async execute(session: AccountSession): Promise<void> {
    await this.executeWithSummary(session);
  }

  async executeWithSummary(session: AccountSession): Promise<ScanCounters> {
    if (this.#activeAccountKey !== null) {
      throw new BackgroundProtectionRunError(
        "scan_conflict",
        `Protection Worker slot is already active for another account.`,
      );
    }
    this.#activeAccountKey = session.policyAccountKey;
    try {
      return await this.inner.executeWithSummary(session);
    } finally {
      this.#activeAccountKey = null;
    }
  }
}
