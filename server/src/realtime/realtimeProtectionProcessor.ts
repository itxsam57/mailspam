import type { WorkerBackgroundProtectionExecutor } from "../api/backgroundProtection.js";
import type { AccountSession, SessionStore } from "../api/sessionStore.js";
import type { Provider } from "../canonical/envelope.js";
import type { CanonicalInboundEventV1, InboundEventProcessingResult } from "./inboundEvents.js";

export type RealtimeProtectionErrorCode = "provider_unavailable" | "provider_mismatch" | "scan_conflict";

export class RealtimeProtectionRunError extends Error {
  constructor(readonly code: RealtimeProtectionErrorCode, message: string) {
    super(message);
    this.name = "RealtimeProtectionRunError";
  }
}

export interface BoundedProtectionExecutor {
  executeWithSummary(session: AccountSession): Promise<{
    examined: number;
    review: number;
    highRisk: number;
    confirmedThreat: number;
    unknown: number;
  }>;
}

function sessionProvider(session: AccountSession): Provider | null {
  return session.provider === "gmail"
    || session.provider === "outlook"
    || session.provider === "icloud"
    || session.provider === "yahoo"
    || session.provider === "imap"
    ? session.provider
    : null;
}

/**
 * Maps a metadata-only arrival/change trigger to the already-accepted bounded
 * Worker protection path. The trigger itself never carries or scores message
 * content, and successful processing is the only point at which the inbound
 * coordinator may acknowledge its replay key/checkpoint.
 */
export class RealtimeProtectionProcessor {
  constructor(
    private readonly sessions: Pick<SessionStore, "canonicalForPolicyAccountKey">,
    private readonly executor: BoundedProtectionExecutor,
  ) {}

  async process(event: Readonly<CanonicalInboundEventV1>): Promise<InboundEventProcessingResult> {
    let session: AccountSession | undefined;
    try {
      session = this.sessions.canonicalForPolicyAccountKey(event.accountKey);
    } catch {
      throw new RealtimeProtectionRunError(
        "provider_mismatch",
        "Mailbox session ownership is ambiguous; reconnect this mailbox before realtime protection continues.",
      );
    }
    if (!session) {
      throw new RealtimeProtectionRunError("provider_unavailable", "The protected mailbox is not connected locally.");
    }
    if (sessionProvider(session) !== event.provider) {
      throw new RealtimeProtectionRunError(
        "provider_mismatch",
        "The inbound provider does not match the connected protected mailbox.",
      );
    }
    if (session.activeScanWorker) {
      throw new RealtimeProtectionRunError("scan_conflict", "A manual, scheduled or realtime scan is already active for this mailbox.");
    }

    const counters = await this.executor.executeWithSummary(session);
    return {
      examined: counters.examined,
      // Review and Unknown both need user-visible caution rather than being
      // collapsed into a false clean result at the realtime boundary.
      warnings: counters.review + counters.unknown,
      highRisk: counters.highRisk,
      confirmedThreat: counters.confirmedThreat,
    };
  }
}

export function createRealtimeProtectionProcessor(
  sessions: Pick<SessionStore, "canonicalForPolicyAccountKey">,
  executor: Pick<WorkerBackgroundProtectionExecutor, "executeWithSummary">,
): RealtimeProtectionProcessor {
  return new RealtimeProtectionProcessor(sessions, executor);
}
