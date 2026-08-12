import { createHash, timingSafeEqual } from "node:crypto";
import type { Provider } from "../canonical/envelope.js";
import type { CanonicalInboundEventV1 } from "./inboundEvents.js";

const MAX_PROVIDER_NOTIFICATION_BYTES = 64 * 1024;
const MAX_METADATA_CHARS = 8192;
const MAX_GRAPH_NOTIFICATIONS = 128;

export interface GmailPushBinding {
  accountKey: string;
  /** Trusted address captured when the Gmail watch is established. */
  expectedEmailAddress: string;
}

export interface MicrosoftGraphBinding {
  accountKey: string;
  subscriptionId: string;
  clientState: string;
  tenantId?: string;
}

export interface ImapIdleBinding {
  accountKey: string;
  provider: "icloud" | "yahoo" | "imap";
  inboxPath: string;
  /** Local generation token rotated whenever the IMAP connection is recreated. */
  connectionGeneration: string;
}

export interface ProviderInboundBatch {
  events: CanonicalInboundEventV1[];
  /** Trigger a provider reconciliation/full sync before accepting a new checkpoint. */
  requiresResync: boolean;
  reason: "notification" | "missed" | "subscription_removed" | "reauthorization_required" | "poll_fallback";
}

export class ProviderInboundSourceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProviderInboundSourceError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function boundedJson(input: unknown): Record<string, unknown> {
  let encoded: Uint8Array;
  try { encoded = new TextEncoder().encode(JSON.stringify(input)); }
  catch { throw new ProviderInboundSourceError("Provider notification is not serializable JSON."); }
  if (encoded.byteLength > MAX_PROVIDER_NOTIFICATION_BYTES) throw new ProviderInboundSourceError("Provider notification exceeds the accepted resource limit.");
  if (!isRecord(input)) throw new ProviderInboundSourceError("Provider notification must be an object.");
  return input;
}

function requiredString(value: unknown, field: string, max = MAX_METADATA_CHARS): string {
  if (typeof value !== "string") throw new ProviderInboundSourceError(`${field} is missing.`);
  const normalized = value.trim();
  if (!normalized || normalized.length > max) throw new ProviderInboundSourceError(`${field} is invalid.`);
  return normalized;
}

function optionalString(value: unknown, field: string, max = MAX_METADATA_CHARS): string | null {
  if (value === undefined || value === null) return null;
  return requiredString(value, field, max);
}

function secureEqual(left: string, right: string): boolean {
  const a = Buffer.from(left, "utf8");
  const b = Buffer.from(right, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

function stableId(namespace: string, fields: string[]): string {
  return createHash("sha256").update(`${namespace}\0${fields.join("\0")}`, "utf8").digest("hex");
}

function normalizeEmailAddress(value: string): string {
  return value.trim().toLowerCase();
}

function decodeBase64UrlJson(data: string): Record<string, unknown> {
  if (data.length > MAX_PROVIDER_NOTIFICATION_BYTES) throw new ProviderInboundSourceError("Gmail notification data exceeds the accepted resource limit.");
  if (!/^[A-Za-z0-9_-]+={0,2}$/.test(data)) throw new ProviderInboundSourceError("Gmail notification data is not valid base64url.");
  let decoded: Buffer;
  try { decoded = Buffer.from(data, "base64url"); }
  catch { throw new ProviderInboundSourceError("Gmail notification data could not be decoded."); }
  if (decoded.length > MAX_PROVIDER_NOTIFICATION_BYTES) throw new ProviderInboundSourceError("Gmail notification data exceeds the accepted resource limit.");
  try {
    const parsed = JSON.parse(decoded.toString("utf8"));
    if (!isRecord(parsed)) throw new Error("not object");
    return parsed;
  } catch {
    throw new ProviderInboundSourceError("Gmail notification data is not valid JSON.");
  }
}

/**
 * Converts a Gmail Cloud Pub/Sub webhook into a metadata-only wake-up event.
 * The decoded email address is used only to bind the webhook to the watch that
 * Email Shield created; it never chooses the local account by itself.
 *
 * The returned checkpoint is a Gmail historyId. The consumer MUST reconcile
 * with users.history.list before treating the checkpoint as complete.
 */
export function normalizeGmailPushNotification(input: unknown, binding: GmailPushBinding): ProviderInboundBatch {
  const root = boundedJson(input);
  if (Object.keys(root).some((key) => key !== "message" && key !== "subscription")) {
    throw new ProviderInboundSourceError("Gmail Pub/Sub notification contains unknown top-level fields.");
  }
  if (!isRecord(root.message)) throw new ProviderInboundSourceError("Gmail Pub/Sub message is missing.");
  const message = root.message;
  const messageId = requiredString(message.messageId ?? message.message_id, "Gmail Pub/Sub messageId");
  const data = requiredString(message.data, "Gmail Pub/Sub data", MAX_PROVIDER_NOTIFICATION_BYTES);
  const payload = decodeBase64UrlJson(data);
  if (Object.keys(payload).some((key) => key !== "emailAddress" && key !== "historyId")) {
    throw new ProviderInboundSourceError("Gmail notification payload contains unknown fields.");
  }
  const emailAddress = requiredString(payload.emailAddress, "Gmail emailAddress");
  const historyId = requiredString(payload.historyId, "Gmail historyId");
  if (!/^\d+$/.test(historyId)) throw new ProviderInboundSourceError("Gmail historyId is invalid.");
  if (!secureEqual(normalizeEmailAddress(emailAddress), normalizeEmailAddress(requiredString(binding.expectedEmailAddress, "Gmail binding emailAddress")))) {
    throw new ProviderInboundSourceError("Gmail notification does not match the watched account.");
  }

  return {
    events: [{
      schemaVersion: 1,
      accountKey: requiredString(binding.accountKey, "Gmail accountKey", 512),
      provider: "gmail",
      source: "push",
      kind: "mailbox_changed",
      eventId: messageId,
      checkpoint: historyId,
      providerMessageId: null,
    }],
    // Gmail push is a wake-up signal; history.list owns precise reconciliation.
    requiresResync: true,
    reason: "notification",
  };
}

interface GraphNotification {
  id: string | null;
  subscriptionId: string;
  tenantId: string;
  clientState: string;
  changeType: string | null;
  lifecycleEvent: string | null;
  resource: string;
  resourceDataId: string | null;
}

function parseGraphNotification(input: unknown): GraphNotification {
  if (!isRecord(input)) throw new ProviderInboundSourceError("Microsoft Graph notification item must be an object.");
  if (input.encryptedContent !== undefined) {
    throw new ProviderInboundSourceError("Email Shield's basic Graph notification endpoint does not accept resource-content notifications.");
  }
  const changeType = optionalString(input.changeType, "Microsoft Graph changeType");
  const lifecycleEvent = optionalString(input.lifecycleEvent, "Microsoft Graph lifecycleEvent");
  if (Boolean(changeType) === Boolean(lifecycleEvent)) {
    throw new ProviderInboundSourceError("Microsoft Graph notification must contain exactly one change or lifecycle type.");
  }
  let resourceDataId: string | null = null;
  if (input.resourceData !== undefined && input.resourceData !== null) {
    if (!isRecord(input.resourceData)) throw new ProviderInboundSourceError("Microsoft Graph resourceData is invalid.");
    resourceDataId = optionalString(input.resourceData.id, "Microsoft Graph resourceData.id");
  }
  return {
    id: optionalString(input.id, "Microsoft Graph notification id"),
    subscriptionId: requiredString(input.subscriptionId, "Microsoft Graph subscriptionId"),
    tenantId: requiredString(input.tenantId, "Microsoft Graph tenantId"),
    clientState: requiredString(input.clientState, "Microsoft Graph clientState", 255),
    changeType,
    lifecycleEvent,
    resource: requiredString(input.resource, "Microsoft Graph resource"),
    resourceDataId,
  };
}

function validateGraphBinding(notification: GraphNotification, binding: MicrosoftGraphBinding): void {
  if (!secureEqual(notification.subscriptionId, requiredString(binding.subscriptionId, "Graph binding subscriptionId"))) {
    throw new ProviderInboundSourceError("Microsoft Graph subscription does not match the trusted binding.");
  }
  if (!secureEqual(notification.clientState, requiredString(binding.clientState, "Graph binding clientState", 255))) {
    throw new ProviderInboundSourceError("Microsoft Graph clientState verification failed.");
  }
  if (binding.tenantId && !secureEqual(notification.tenantId, requiredString(binding.tenantId, "Graph binding tenantId"))) {
    throw new ProviderInboundSourceError("Microsoft Graph tenant does not match the trusted binding.");
  }
}

/**
 * Normalizes basic Microsoft Graph message notifications. Resource content is
 * deliberately not accepted here; the local provider adapter fetches the
 * message under the user's existing authorization after clientState binding.
 */
export function normalizeMicrosoftGraphNotifications(input: unknown, binding: MicrosoftGraphBinding): ProviderInboundBatch {
  const root = boundedJson(input);
  if (Object.keys(root).some((key) => key !== "value" && key !== "validationTokens")) {
    throw new ProviderInboundSourceError("Microsoft Graph notification contains unknown top-level fields.");
  }
  if (!Array.isArray(root.value) || root.value.length === 0 || root.value.length > MAX_GRAPH_NOTIFICATIONS) {
    throw new ProviderInboundSourceError("Microsoft Graph notification batch is invalid.");
  }
  // validationTokens belong to rich notifications. This endpoint uses basic
  // notifications and therefore authenticates each item with trusted clientState.
  if (root.validationTokens !== undefined) {
    throw new ProviderInboundSourceError("Rich Microsoft Graph notifications are not accepted by this metadata-only endpoint.");
  }

  const events: CanonicalInboundEventV1[] = [];
  let lifecycleReason: ProviderInboundBatch["reason"] | null = null;
  for (const raw of root.value) {
    const item = parseGraphNotification(raw);
    validateGraphBinding(item, binding);
    if (item.lifecycleEvent) {
      if (item.lifecycleEvent === "missed") lifecycleReason = "missed";
      else if (item.lifecycleEvent === "subscriptionRemoved") lifecycleReason = "subscription_removed";
      else if (item.lifecycleEvent === "reauthorizationRequired") lifecycleReason = "reauthorization_required";
      else throw new ProviderInboundSourceError("Unsupported Microsoft Graph lifecycle event.");
      continue;
    }
    if (item.changeType !== "created") continue;
    const eventId = item.id ?? stableId("email-shield-graph-basic-notification-v1", [
      item.subscriptionId,
      item.tenantId,
      item.changeType,
      item.resource,
      item.resourceDataId ?? "",
    ]);
    events.push({
      schemaVersion: 1,
      accountKey: requiredString(binding.accountKey, "Graph accountKey", 512),
      provider: "outlook",
      source: "push",
      kind: item.resourceDataId ? "message_arrived" : "mailbox_changed",
      eventId,
      checkpoint: null,
      providerMessageId: item.resourceDataId,
    });
  }

  return {
    events,
    requiresResync: lifecycleReason !== null,
    reason: lifecycleReason ?? "notification",
  };
}

/** Converts the local ImapFlow `exists` event into a wake-up signal. */
export function normalizeImapExistsSignal(
  input: unknown,
  binding: ImapIdleBinding,
): ProviderInboundBatch {
  const value = boundedJson(input);
  if (Object.keys(value).some((key) => key !== "path" && key !== "count" && key !== "prevCount" && key !== "sequence")) {
    throw new ProviderInboundSourceError("IMAP exists signal contains unknown fields.");
  }
  const path = requiredString(value.path, "IMAP path");
  if (!secureEqual(path, requiredString(binding.inboxPath, "IMAP binding inbox path"))) {
    return { events: [], requiresResync: false, reason: "notification" };
  }
  const count = Number(value.count);
  const prevCount = Number(value.prevCount);
  const sequence = Number(value.sequence);
  if (!Number.isSafeInteger(count) || count < 0 || !Number.isSafeInteger(prevCount) || prevCount < 0 || !Number.isSafeInteger(sequence) || sequence < 0) {
    throw new ProviderInboundSourceError("IMAP exists counters are invalid.");
  }
  if (count <= prevCount) return { events: [], requiresResync: false, reason: "notification" };
  const provider = binding.provider;
  if (!(["icloud", "yahoo", "imap"] as Provider[]).includes(provider)) {
    throw new ProviderInboundSourceError("IMAP source provider is invalid.");
  }
  return {
    events: [{
      schemaVersion: 1,
      accountKey: requiredString(binding.accountKey, "IMAP accountKey", 512),
      provider,
      source: "idle",
      kind: "mailbox_changed",
      eventId: stableId("email-shield-imap-exists-v1", [
        requiredString(binding.connectionGeneration, "IMAP connection generation"),
        path,
        String(sequence),
        String(prevCount),
        String(count),
      ]),
      checkpoint: null,
      providerMessageId: null,
    }],
    requiresResync: false,
    reason: "notification",
  };
}

/** Creates a bounded polling fallback trigger without fabricating provider change details. */
export function createPollingFallbackEvent(params: {
  accountKey: string;
  provider: Provider;
  pollGeneration: string;
  sequence: number;
}): ProviderInboundBatch {
  if (!Number.isSafeInteger(params.sequence) || params.sequence < 0) throw new ProviderInboundSourceError("Polling sequence is invalid.");
  if (!(["gmail", "icloud", "outlook", "yahoo", "imap"] as Provider[]).includes(params.provider)) {
    throw new ProviderInboundSourceError("Polling provider is invalid.");
  }
  return {
    events: [{
      schemaVersion: 1,
      accountKey: requiredString(params.accountKey, "Polling accountKey", 512),
      provider: params.provider,
      source: "poll",
      kind: "mailbox_changed",
      eventId: stableId("email-shield-poll-fallback-v1", [
        requiredString(params.pollGeneration, "Polling generation"),
        String(params.sequence),
      ]),
      checkpoint: null,
      providerMessageId: null,
    }],
    requiresResync: false,
    reason: "poll_fallback",
  };
}
