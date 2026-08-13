import type { CanonicalEnvelope } from "../canonical/envelope.js";

export const INBOX_HEALTH_MAX_MESSAGES = 200;
export const INBOX_HEALTH_MAX_SUBSCRIPTIONS = 100;
export const INBOX_HEALTH_MAX_CLEANUP_GROUPS = 100;

export interface SubscriptionInventoryItem {
  key: string;
  displayName: string;
  senderAddress: string | null;
  senderDomain: string | null;
  messages: number;
  newestAt: string | null;
  oldestAt: string | null;
  oneClickEligibleMessages: number;
  unsubscribeAvailable: boolean;
}

export interface InboxCleanupGroup {
  key: string;
  senderAddress: string | null;
  senderDomain: string | null;
  messages: number;
  messagesOlderThan30Days: number;
  newestAt: string | null;
  oldestAt: string | null;
  category: "newsletter" | "bulk_sender" | "first_contact";
  destructiveActionRequiresConfirmation: true;
}

export interface InboxHealthSnapshot {
  schemaVersion: 1;
  generatedAt: string;
  inspectedMessages: number;
  incomplete: boolean;
  incompleteReasons: string[];
  volume: {
    inbox: number;
    spam: number;
    archive: number;
    other: number;
    approximateBytes: number;
  };
  subscriptions: SubscriptionInventoryItem[];
  cleanupGroups: InboxCleanupGroup[];
  firstContactMessages: number;
  unreadableOrPartialMessages: number;
  privacy: "local_mailbox_analysis_not_uploaded";
}

function validTimestamp(value: string): number | null {
  const time = Date.parse(value);
  return Number.isFinite(time) ? time : null;
}

function isoOrNull(value: number | null): string | null {
  return value === null ? null : new Date(value).toISOString();
}

function senderKey(envelope: CanonicalEnvelope): string {
  return envelope.listHeaders.listId?.trim().toLowerCase()
    || envelope.from.address?.trim().toLowerCase()
    || envelope.from.domain?.trim().toLowerCase()
    || `unknown:${envelope.providerNativeId}`;
}

function displayName(envelope: CanonicalEnvelope): string {
  return envelope.from.displayName?.trim()
    || envelope.from.address?.trim()
    || envelope.from.domain?.trim()
    || "Unknown sender";
}

interface MutableGroup {
  key: string;
  displayName: string;
  senderAddress: string | null;
  senderDomain: string | null;
  messages: number;
  newest: number | null;
  oldest: number | null;
  oneClickEligibleMessages: number;
  unsubscribeAvailable: boolean;
  newsletter: boolean;
  firstContacts: number;
  olderThan30Days: number;
}

export function analyzeInboxHealth(
  envelopes: readonly CanonicalEnvelope[],
  options: { now?: number; sourceIncomplete?: boolean; sourceIncompleteReasons?: readonly string[] } = {},
): InboxHealthSnapshot {
  const now = options.now ?? Date.now();
  const bounded = envelopes.slice(0, INBOX_HEALTH_MAX_MESSAGES);
  const groups = new Map<string, MutableGroup>();
  let approximateBytes = 0;
  let firstContactMessages = 0;
  let unreadableOrPartialMessages = 0;
  const volume = { inbox: 0, spam: 0, archive: 0, other: 0, approximateBytes: 0 };

  for (const envelope of bounded) {
    approximateBytes += Math.max(0, Math.min(100 * 1024 * 1024, envelope.diagnostics.sizeBytes || 0));
    if (envelope.folder === "inbox") volume.inbox += 1;
    else if (envelope.folder === "spam") volume.spam += 1;
    else if (envelope.folder === "archive") volume.archive += 1;
    else volume.other += 1;
    if (envelope.threadContext.isFirstContact) firstContactMessages += 1;
    if (envelope.parseStatus !== "complete" || envelope.diagnostics.contentCoverage === "insufficient") unreadableOrPartialMessages += 1;

    const key = senderKey(envelope);
    let group = groups.get(key);
    if (!group) {
      group = {
        key,
        displayName: displayName(envelope),
        senderAddress: envelope.from.address,
        senderDomain: envelope.from.domain,
        messages: 0,
        newest: null,
        oldest: null,
        oneClickEligibleMessages: 0,
        unsubscribeAvailable: false,
        newsletter: false,
        firstContacts: 0,
        olderThan30Days: 0,
      };
      groups.set(key, group);
    }
    group.messages += 1;
    group.firstContacts += envelope.threadContext.isFirstContact ? 1 : 0;
    const timestamp = validTimestamp(envelope.date);
    if (timestamp !== null) {
      group.newest = group.newest === null ? timestamp : Math.max(group.newest, timestamp);
      group.oldest = group.oldest === null ? timestamp : Math.min(group.oldest, timestamp);
      if (timestamp <= now - 30 * 24 * 60 * 60 * 1_000) group.olderThan30Days += 1;
    }
    const hasUnsubscribe = Boolean(envelope.listHeaders.listUnsubscribe);
    const oneClick = envelope.listHeaders.oneClickHeaderSetUnambiguous === true
      && /one-click/i.test(envelope.listHeaders.listUnsubscribePost ?? "");
    if (oneClick) group.oneClickEligibleMessages += 1;
    if (hasUnsubscribe) group.unsubscribeAvailable = true;
    if (envelope.listHeaders.listId || hasUnsubscribe) group.newsletter = true;
  }

  volume.approximateBytes = approximateBytes;
  const allGroups = [...groups.values()];
  const subscriptions = allGroups
    .filter((group) => group.newsletter)
    .sort((left, right) => right.messages - left.messages)
    .slice(0, INBOX_HEALTH_MAX_SUBSCRIPTIONS)
    .map((group): SubscriptionInventoryItem => ({
      key: group.key,
      displayName: group.displayName,
      senderAddress: group.senderAddress,
      senderDomain: group.senderDomain,
      messages: group.messages,
      newestAt: isoOrNull(group.newest),
      oldestAt: isoOrNull(group.oldest),
      oneClickEligibleMessages: group.oneClickEligibleMessages,
      unsubscribeAvailable: group.unsubscribeAvailable,
    }));

  const cleanupGroups = allGroups
    .filter((group) => group.newsletter || group.messages >= 3 || group.firstContacts === group.messages)
    .sort((left, right) => right.messages - left.messages)
    .slice(0, INBOX_HEALTH_MAX_CLEANUP_GROUPS)
    .map((group): InboxCleanupGroup => ({
      key: group.key,
      senderAddress: group.senderAddress,
      senderDomain: group.senderDomain,
      messages: group.messages,
      messagesOlderThan30Days: group.olderThan30Days,
      newestAt: isoOrNull(group.newest),
      oldestAt: isoOrNull(group.oldest),
      category: group.newsletter ? "newsletter" : group.firstContacts === group.messages ? "first_contact" : "bulk_sender",
      destructiveActionRequiresConfirmation: true,
    }));

  const incompleteReasons = [...(options.sourceIncompleteReasons ?? [])];
  if (envelopes.length > INBOX_HEALTH_MAX_MESSAGES) incompleteReasons.push(`Analysis was bounded to ${INBOX_HEALTH_MAX_MESSAGES} messages.`);
  if (unreadableOrPartialMessages > 0) incompleteReasons.push("One or more messages were partial or unreadable and were not treated as clean.");
  const incomplete = options.sourceIncomplete === true || incompleteReasons.length > 0;

  return {
    schemaVersion: 1,
    generatedAt: new Date(now).toISOString(),
    inspectedMessages: bounded.length,
    incomplete,
    incompleteReasons: [...new Set(incompleteReasons)].slice(0, 20),
    volume,
    subscriptions,
    cleanupGroups,
    firstContactMessages,
    unreadableOrPartialMessages,
    privacy: "local_mailbox_analysis_not_uploaded",
  };
}
