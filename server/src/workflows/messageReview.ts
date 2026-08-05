import { createHash } from "node:crypto";
import type { CanonicalEnvelope } from "../canonical/envelope.js";

/**
 * Produces an account-scoped, provider-neutral key for one exact message.
 * The persisted value contains no subject, sender, provider ID, body, or raw
 * mailbox address. It remains stable when the provider exposes a stable
 * Message-ID and falls back to the provider-native identifier when required.
 */
export function messageExceptionKey(envelope: CanonicalEnvelope): string {
  const stableMessageIdentity = envelope.messageId || envelope.providerNativeId;
  const digest = createHash("sha256")
    .update("email-shield-message-exception-v1\0", "utf8")
    .update(envelope.accountProof, "utf8")
    .update("\0", "utf8")
    .update(envelope.provider, "utf8")
    .update("\0", "utf8")
    .update(stableMessageIdentity, "utf8")
    .update("\0", "utf8")
    .update(envelope.from.address?.toLowerCase() ?? "", "utf8")
    .digest("hex");
  return `message:${digest}`;
}

export function isMessageExceptionKey(value: string): boolean {
  return /^message:[a-f0-9]{64}$/.test(value);
}
