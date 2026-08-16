import type { AccountSession } from "../api/sessionStore.js";
import { createAdapter } from "../api/adapterConfig.js";
import type { CredentialVault } from "../security/credentialVault.js";

export const DEFAULT_MAILBOX_CHECKPOINT_TIMEOUT_MS = 35_000;

export interface MailboxCheckpointProbe {
  checkpoint(session: AccountSession): Promise<string | null>;
}

/**
 * Opens a short-lived provider connection solely for metadata change detection.
 * Provider adapters own the metadata primitive; this layer never lists or
 * downloads messages and never exposes the returned checkpoint outside local
 * protected realtime state.
 */
export class AdapterMailboxCheckpointProbe implements MailboxCheckpointProbe {
  constructor(
    private readonly credentialVault: CredentialVault,
    private readonly timeoutMs = DEFAULT_MAILBOX_CHECKPOINT_TIMEOUT_MS,
  ) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 5_000 || timeoutMs > 120_000) {
      throw new Error("Mailbox checkpoint timeout is outside the accepted bounds.");
    }
  }

  async checkpoint(session: AccountSession): Promise<string | null> {
    if (session.closing) return null;
    const adapter = createAdapter(session.config, this.credentialVault);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    timeout.unref();
    try {
      await adapter.connect(controller.signal);
      const checkpoint = adapter.mailboxCheckpoint
        ? await adapter.mailboxCheckpoint(controller.signal)
        : null;
      if (checkpoint === null) return null;
      const normalized = checkpoint.trim().toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(normalized)) {
        throw new Error("Provider mailbox checkpoint was not an opaque SHA-256 digest.");
      }
      return normalized;
    } finally {
      clearTimeout(timeout);
      await adapter.disconnect().catch(() => {});
    }
  }
}
