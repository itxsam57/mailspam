import { describe, expect, it } from "vitest";
import {
  createPollingFallbackEvent,
  normalizeGmailPushNotification,
  normalizeImapExistsSignal,
  normalizeMicrosoftGraphNotifications,
  ProviderInboundSourceError,
} from "../../server/src/realtime/providerSources.js";

function gmailPayload(emailAddress = "owner@example.com", historyId = "9876543210") {
  return {
    message: {
      data: Buffer.from(JSON.stringify({ emailAddress, historyId }), "utf8").toString("base64url"),
      messageId: "2070443601311540",
      publishTime: "2026-08-13T00:00:00Z",
    },
    subscription: "projects/project/subscriptions/email-shield",
  };
}

describe("provider inbound source normalization", () => {
  it("converts Gmail Pub/Sub into a history reconciliation trigger bound to the watched account", () => {
    const result = normalizeGmailPushNotification(gmailPayload(), {
      accountKey: "a".repeat(64),
      expectedEmailAddress: "OWNER@example.com",
    });
    expect(result.requiresResync).toBe(true);
    expect(result.events).toEqual([{
      schemaVersion: 1,
      accountKey: "a".repeat(64),
      provider: "gmail",
      source: "push",
      kind: "mailbox_changed",
      eventId: "2070443601311540",
      checkpoint: "9876543210",
      providerMessageId: null,
    }]);
  });

  it("rejects a Gmail notification that tries to select another local account", () => {
    expect(() => normalizeGmailPushNotification(gmailPayload("attacker@example.com"), {
      accountKey: "a".repeat(64),
      expectedEmailAddress: "owner@example.com",
    })).toThrow(/does not match the watched account/i);
  });

  it("rejects malformed and expanded Gmail payloads instead of silently trusting them", () => {
    expect(() => normalizeGmailPushNotification({ message: { data: "***", messageId: "1" } }, {
      accountKey: "a".repeat(64),
      expectedEmailAddress: "owner@example.com",
    })).toThrow(ProviderInboundSourceError);

    const data = Buffer.from(JSON.stringify({
      emailAddress: "owner@example.com",
      historyId: "2",
      rawMessage: "private content must never arrive here",
    })).toString("base64url");
    expect(() => normalizeGmailPushNotification({ message: { data, messageId: "1" } }, {
      accountKey: "a".repeat(64),
      expectedEmailAddress: "owner@example.com",
    })).toThrow(/unknown fields/i);
  });

  it("authenticates a basic Microsoft Graph message notification with trusted clientState", () => {
    const result = normalizeMicrosoftGraphNotifications({
      value: [{
        id: "notification-1",
        subscriptionId: "sub-1",
        subscriptionExpirationDateTime: "2026-08-14T00:00:00Z",
        changeType: "created",
        resource: "Users/user-id/Messages/message-1",
        resourceData: {
          "@odata.type": "#Microsoft.Graph.Message",
          "@odata.id": "Users/user-id/Messages/message-1",
          id: "message-1",
        },
        clientState: "a-long-random-client-state",
        tenantId: "tenant-1",
      }],
    }, {
      accountKey: "b".repeat(64),
      subscriptionId: "sub-1",
      clientState: "a-long-random-client-state",
      tenantId: "tenant-1",
    });

    expect(result).toEqual({
      events: [{
        schemaVersion: 1,
        accountKey: "b".repeat(64),
        provider: "outlook",
        source: "push",
        kind: "message_arrived",
        eventId: "notification-1",
        checkpoint: null,
        providerMessageId: "message-1",
      }],
      requiresResync: false,
      reason: "notification",
    });
  });

  it("fails Graph basic notifications closed when clientState or subscription binding is wrong", () => {
    const body = {
      value: [{
        subscriptionId: "sub-1",
        subscriptionExpirationDateTime: "2026-08-14T00:00:00Z",
        changeType: "created",
        resource: "Users/user-id/Messages/message-1",
        clientState: "wrong-state",
        tenantId: "tenant-1",
      }],
    };
    expect(() => normalizeMicrosoftGraphNotifications(body, {
      accountKey: "b".repeat(64),
      subscriptionId: "sub-1",
      clientState: "expected-state",
    })).toThrow(/clientState verification failed/i);
  });

  it("does not accept rich Graph payloads on the metadata-only ingress", () => {
    expect(() => normalizeMicrosoftGraphNotifications({
      validationTokens: ["jwt"],
      value: [{
        subscriptionId: "sub-1",
        subscriptionExpirationDateTime: "2026-08-14T00:00:00Z",
        changeType: "created",
        resource: "Users/user-id/Messages/message-1",
        clientState: "state",
        tenantId: "tenant-1",
        encryptedContent: { data: "private-data" },
      }],
    }, {
      accountKey: "b".repeat(64),
      subscriptionId: "sub-1",
      clientState: "state",
    })).toThrow(/rich Microsoft Graph notifications are not accepted|does not accept resource-content/i);
  });

  it.each([
    ["missed", "missed"],
    ["subscriptionRemoved", "subscription_removed"],
    ["reauthorizationRequired", "reauthorization_required"],
  ] as const)("turns Graph lifecycle %s into an explicit resync requirement", (lifecycleEvent, reason) => {
    const result = normalizeMicrosoftGraphNotifications({
      value: [{
        subscriptionId: "sub-1",
        subscriptionExpirationDateTime: "2026-08-14T00:00:00Z",
        lifecycleEvent,
        resource: "Users/user-id/Messages",
        clientState: "state",
        tenantId: "tenant-1",
      }],
    }, {
      accountKey: "b".repeat(64),
      subscriptionId: "sub-1",
      clientState: "state",
    });
    expect(result.events).toEqual([]);
    expect(result.requiresResync).toBe(true);
    expect(result.reason).toBe(reason);
  });

  it("normalizes only an INBOX growth signal from local IMAP IDLE", () => {
    const binding = {
      accountKey: "c".repeat(64),
      provider: "yahoo" as const,
      inboxPath: "INBOX",
      connectionGeneration: "connection-7",
    };
    const result = normalizeImapExistsSignal({ path: "INBOX", count: 11, prevCount: 10, sequence: 4 }, binding);
    expect(result.events).toHaveLength(1);
    expect(result.events[0]).toMatchObject({ provider: "yahoo", source: "idle", kind: "mailbox_changed" });
    expect(result.events[0]!.eventId).toMatch(/^[0-9a-f]{64}$/);

    expect(normalizeImapExistsSignal({ path: "Sent", count: 3, prevCount: 2, sequence: 5 }, binding).events).toEqual([]);
    expect(normalizeImapExistsSignal({ path: "INBOX", count: 10, prevCount: 10, sequence: 6 }, binding).events).toEqual([]);
  });

  it("creates opaque bounded polling fallback events without claiming a message arrived", () => {
    const result = createPollingFallbackEvent({
      accountKey: "d".repeat(64),
      provider: "icloud",
      pollGeneration: "boot-1",
      sequence: 9,
    });
    expect(result.reason).toBe("poll_fallback");
    expect(result.events[0]).toMatchObject({
      provider: "icloud",
      source: "poll",
      kind: "mailbox_changed",
      providerMessageId: null,
    });
    expect(result.events[0]!.eventId).toMatch(/^[0-9a-f]{64}$/);
  });
});
