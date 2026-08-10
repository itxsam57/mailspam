import type { CanonicalEnvelope } from "../canonical/envelope.js";
import { sha256Hex } from "../core/sha256.js";

/**
 * Produces an account-scoped, provider-neutral key for one exact message.
 * The persisted value contains no subject, sender, provider ID, body, or raw
 * mailbox address. It remains stable when the provider exposes a stable
 * Message-ID and falls back to the provider-native identifier when required.
 */
export function messageExceptionKey(envelope: CanonicalEnvelope): string {
  const stableMessageIdentity = envelope.messageId || envelope.providerNativeId;
  const digest = sha256Hex([
    "email-shield-message-exception-v1",
    envelope.accountProof,
    envelope.provider,
    stableMessageIdentity,
    envelope.from.address?.toLowerCase() ?? "",
  ].join("\0"));
  return `message:${digest}`;
}

export function isMessageExceptionKey(value: string): boolean {
  return /^message:[a-f0-9]{64}$/.test(value);
}
