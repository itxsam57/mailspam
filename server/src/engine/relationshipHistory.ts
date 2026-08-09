import { createHmac, timingSafeEqual } from "node:crypto";
import type { CanonicalEnvelope, NormalizedFolder } from "../canonical/envelope.js";
import type { Verdict } from "./verdict.js";
import { authenticationPassed } from "./identitySignals.js";

export interface RelationshipProfile {
  messagesSeen: number;
  authenticatedMessages: number;
  safeMessages: number;
  reviewMessages: number;
  highRiskMessages: number;
  confirmedThreatMessages: number;
  unknownMessages: number;
  firstObservedAt: number;
  lastObservedAt: number;
  lastAuthenticatedAt: number | null;
  folderCounts: Partial<Record<NormalizedFolder, number>>;
  replyToCounts: Record<string, number>;
}

export interface RelationshipObservation {
  senderKey: string;
  messageKey: string;
  replyToKey: string | null;
  observedAt: number;
  folder: NormalizedFolder;
  authenticated: boolean;
  verdict: Verdict;
}

export interface RelationshipHistoryWorkerSnapshot {
  /** Process-local HMAC key. It is never persisted in this snapshot or returned to browser JavaScript. */
  indexKey: string;
  records: Record<string, RelationshipProfile>;
  /** HMAC message keys only. Structured-cloned into the Worker for replay-safe scans and thread-reference matching. */
  seenMessageKeys: Set<string>;
}

interface ThreadReferenceState {
  knownReference: boolean;
  knownInReplyTo: boolean;
  hasReferenceChain: boolean;
  inReplyToIncludedInReferences: boolean;
}

const INDEX_KEY_BYTES = 32;
const MAX_REPLY_TO_KEYS_PER_PROFILE = 8;

function decodeIndexKey(indexKey: string): Buffer {
  const normalized = indexKey.trim();
  const key = Buffer.from(normalized, "base64");
  if (key.length !== INDEX_KEY_BYTES || key.toString("base64") !== normalized) {
    throw new Error("Relationship-history index key is invalid.");
  }
  return key;
}

function boundedIncrement(value: number): number {
  return Number.isSafeInteger(value) && value >= 0
    ? Math.min(Number.MAX_SAFE_INTEGER, value + 1)
    : 1;
}

export function relationshipIdentityKey(
  indexKey: string,
  namespace: "sender" | "message" | "reply-to",
  value: string,
): string {
  const normalized = value.trim().toLowerCase();
  if (!normalized) return "";
  return createHmac("sha256", decodeIndexKey(indexKey))
    .update(`email-shield-relationship-${namespace}-v1\0`, "utf8")
    .update(normalized, "utf8")
    .digest("hex");
}

export function cloneRelationshipProfile(profile: RelationshipProfile): RelationshipProfile {
  return {
    ...profile,
    folderCounts: { ...profile.folderCounts },
    replyToCounts: { ...profile.replyToCounts },
  };
}

export function relationshipSuspiciousMessages(profile: RelationshipProfile): number {
  return profile.reviewMessages + profile.highRiskMessages + profile.confirmedThreatMessages;
}

/**
 * Establishment is intentionally conservative. Merely seeing an address before
 * is never enough to trust it. At least three prior observations, two locally
 * Safe messages and two authenticated messages are required, and any prior
 * Review/High Risk/Confirmed Threat finding prevents the relationship reward.
 */
export function hasEstablishedRelationship(profile: RelationshipProfile | undefined): boolean {
  if (!profile) return false;
  return profile.messagesSeen >= 3
    && profile.safeMessages >= 2
    && profile.authenticatedMessages >= 2
    && relationshipSuspiciousMessages(profile) === 0;
}

function explicitAuthenticationFailure(envelope: CanonicalEnvelope): boolean {
  const auth = envelope.authentication;
  if (auth.dmarc === "fail") return true;
  if (auth.spf === "fail" && auth.dkim === "fail") return true;
  if (auth.spf === "softfail" && auth.dkim === "fail") return true;
  return false;
}

function stableHistoricalReplyTo(profile: RelationshipProfile): string | null {
  const entries = Object.entries(profile.replyToCounts)
    .filter(([key, count]) => /^[a-f0-9]{64}$/.test(key) && Number.isFinite(count) && count > 0)
    .sort((left, right) => right[1] - left[1]);
  if (entries.length !== 1 || (entries[0]?.[1] ?? 0) < 2) return null;
  return entries[0]![0];
}

function messageReferenceKey(
  envelope: CanonicalEnvelope,
  snapshot: RelationshipHistoryWorkerSnapshot,
  messageId: string,
): string {
  return relationshipIdentityKey(snapshot.indexKey, "message", `${envelope.provider}\0${messageId}`);
}

/**
 * Consumes transient raw RFC thread identifiers before any scoring/browser
 * result can exist. Matching happens only in the account-specific HMAC space
 * already used by the replay index; raw References/In-Reply-To values are not
 * copied into observations or persistent relationship state.
 */
function consumeThreadReferences(
  envelope: CanonicalEnvelope,
  snapshot: RelationshipHistoryWorkerSnapshot | undefined,
): ThreadReferenceState {
  const pending = envelope.threadContext.pendingThreadReferences;
  delete envelope.threadContext.pendingThreadReferences;
  if (!pending || !snapshot) {
    return {
      knownReference: false,
      knownInReplyTo: false,
      hasReferenceChain: Boolean(pending?.references.length),
      inReplyToIncludedInReferences: true,
    };
  }

  const inReplyToKey = pending.inReplyTo
    ? messageReferenceKey(envelope, snapshot, pending.inReplyTo)
    : null;
  const referenceKeys = pending.references.map((messageId) => messageReferenceKey(envelope, snapshot, messageId));
  const knownInReplyTo = Boolean(inReplyToKey && snapshot.seenMessageKeys.has(inReplyToKey));
  const knownReference = knownInReplyTo || referenceKeys.some((key) => snapshot.seenMessageKeys.has(key));

  return {
    knownReference,
    knownInReplyTo,
    hasReferenceChain: referenceKeys.length > 0,
    inReplyToIncludedInReferences: !inReplyToKey || referenceKeys.length === 0 || referenceKeys.includes(inReplyToKey),
  };
}

/**
 * Enriches the canonical relationship signals from prior local history. The
 * sender address itself never enters the persisted relationship database; it
 * is converted to an HMAC fingerprint inside the Worker. Established history
 * does not mutate `isFirstContact`; first-contact-specific threat rules stay
 * active even if a known sender account is later compromised.
 */
export function annotateRelationshipHistory(
  envelope: CanonicalEnvelope,
  snapshot: RelationshipHistoryWorkerSnapshot | undefined,
): string | null {
  const threadReferences = consumeThreadReferences(envelope, snapshot);
  const address = envelope.from.address?.trim().toLowerCase() ?? "";
  if (!snapshot || !address) return null;

  const senderKey = relationshipIdentityKey(snapshot.indexKey, "sender", address);
  const profile = snapshot.records[senderKey];
  const suspicious = profile ? relationshipSuspiciousMessages(profile) : 0;
  const established = hasEstablishedRelationship(profile);

  envelope.threadContext.relationshipPriorMessages = profile?.messagesSeen ?? 0;
  envelope.threadContext.relationshipPriorAuthenticatedMessages = profile?.authenticatedMessages ?? 0;
  envelope.threadContext.relationshipPriorSafeMessages = profile?.safeMessages ?? 0;
  envelope.threadContext.relationshipPriorSuspiciousMessages = suspicious;
  envelope.threadContext.hasEstablishedSenderHistory = established;

  envelope.threadContext.relationshipAuthenticationDowngrade = Boolean(
    established && explicitAuthenticationFailure(envelope),
  );

  if (
    established
    && threadReferences.knownInReplyTo
    && threadReferences.hasReferenceChain
    && !threadReferences.inReplyToIncludedInReferences
  ) {
    envelope.threadContext.threadContinuityBroken = true;
  }

  const historicalReplyTo = profile ? stableHistoricalReplyTo(profile) : null;
  const currentReplyTo = envelope.replyTo?.address
    ? relationshipIdentityKey(snapshot.indexKey, "reply-to", envelope.replyTo.address)
    : null;
  const replyToChanged = Boolean(
    established
      && historicalReplyTo
      && currentReplyTo
      && !timingSafeEqual(Buffer.from(historicalReplyTo, "hex"), Buffer.from(currentReplyTo, "hex")),
  );

  if (replyToChanged && threadReferences.knownReference) {
    // A known local parent/ancestor makes this a specific mid-thread route
    // change. Do not also emit the broader relationship-level change.
    envelope.threadContext.replyToChangedMidThread = true;
    envelope.threadContext.replyToChangedFromRelationshipHistory = false;
  } else {
    envelope.threadContext.replyToChangedFromRelationshipHistory = replyToChanged;
  }

  return senderKey;
}

function emptyProfile(observedAt: number): RelationshipProfile {
  return {
    messagesSeen: 0,
    authenticatedMessages: 0,
    safeMessages: 0,
    reviewMessages: 0,
    highRiskMessages: 0,
    confirmedThreatMessages: 0,
    unknownMessages: 0,
    firstObservedAt: observedAt,
    lastObservedAt: observedAt,
    lastAuthenticatedAt: null,
    folderCounts: {},
    replyToCounts: {},
  };
}

export function createRelationshipObservation(
  envelope: CanonicalEnvelope,
  verdict: Verdict,
  snapshot: RelationshipHistoryWorkerSnapshot | undefined,
  observedAt = Date.now(),
): RelationshipObservation | null {
  const sender = envelope.from.address?.trim().toLowerCase() ?? "";
  if (!snapshot || !sender) return null;

  const senderKey = relationshipIdentityKey(snapshot.indexKey, "sender", sender);
  const messageIdentity = `${envelope.provider}\0${envelope.messageId || envelope.providerNativeId}`;
  const messageKey = relationshipIdentityKey(snapshot.indexKey, "message", messageIdentity);
  const replyToKey = envelope.replyTo?.address
    ? relationshipIdentityKey(snapshot.indexKey, "reply-to", envelope.replyTo.address)
    : null;

  return {
    senderKey,
    messageKey,
    replyToKey,
    observedAt: Math.max(1, Math.floor(observedAt)),
    folder: envelope.folder,
    authenticated: authenticationPassed(envelope),
    verdict,
  };
}

/**
 * Applies one observation only once per message fingerprint. Worker replay and
 * persistent merge therefore share the same idempotency rule.
 */
export function applyRelationshipObservationToSnapshot(
  snapshot: RelationshipHistoryWorkerSnapshot | undefined,
  observation: RelationshipObservation | null,
): boolean {
  if (!snapshot || !observation || snapshot.seenMessageKeys.has(observation.messageKey)) return false;
  const current = snapshot.records[observation.senderKey]
    ? cloneRelationshipProfile(snapshot.records[observation.senderKey]!)
    : emptyProfile(observation.observedAt);

  current.messagesSeen = boundedIncrement(current.messagesSeen);
  if (observation.authenticated) {
    current.authenticatedMessages = boundedIncrement(current.authenticatedMessages);
    current.lastAuthenticatedAt = Math.max(current.lastAuthenticatedAt ?? 0, observation.observedAt);
  }

  const eligibleSafeFolder = !["spam", "trash", "drafts"].includes(observation.folder);
  if (observation.verdict === "safe" && eligibleSafeFolder) current.safeMessages = boundedIncrement(current.safeMessages);
  else if (observation.verdict === "review") current.reviewMessages = boundedIncrement(current.reviewMessages);
  else if (observation.verdict === "high_risk") current.highRiskMessages = boundedIncrement(current.highRiskMessages);
  else if (observation.verdict === "confirmed_threat") current.confirmedThreatMessages = boundedIncrement(current.confirmedThreatMessages);
  else if (observation.verdict === "unknown") current.unknownMessages = boundedIncrement(current.unknownMessages);

  current.firstObservedAt = Math.min(current.firstObservedAt || observation.observedAt, observation.observedAt);
  current.lastObservedAt = Math.max(current.lastObservedAt, observation.observedAt);
  current.folderCounts[observation.folder] = boundedIncrement(current.folderCounts[observation.folder] ?? 0);

  if (observation.replyToKey) {
    current.replyToCounts[observation.replyToKey] = boundedIncrement(current.replyToCounts[observation.replyToKey] ?? 0);
    const ordered = Object.entries(current.replyToCounts).sort((left, right) => right[1] - left[1]);
    current.replyToCounts = Object.fromEntries(ordered.slice(0, MAX_REPLY_TO_KEYS_PER_PROFILE));
  }

  snapshot.records[observation.senderKey] = current;
  snapshot.seenMessageKeys.add(observation.messageKey);
  return true;
}
