import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import {
  analyzeInboxHealth,
} from "../../server/src/consumer/inboxHealth.js";
import { discoverDigitalAccountFootprint } from "../../server/src/consumer/digitalFootprint.js";
import * as inboxHealthModule from "../../server/src/consumer/inboxHealth.js";

const root = join(import.meta.dirname, "../..");
const consumerProduct = readFileSync(join(root, "web/consumer-product.js"), "utf8");
const cleanupController = readFileSync(join(root, "web/health-cleanup-controller.js"), "utf8");
const protectionRoutes = readFileSync(join(root, "server/src/api/consumerProtectionRoutes.ts"), "utf8");
const healthWorker = readFileSync(join(root, "server/src/workers/consumerHealthWorker.ts"), "utf8");

function envelope(input: {
  nativeId: string;
  subject: string;
  preview?: string;
  fromDomain?: string;
  fromAddress?: string;
  displayName?: string;
  listId?: string | null;
  unsubscribe?: string | null;
  date?: string;
}): CanonicalEnvelope {
  const fromDomain = input.fromDomain ?? "example.test";
  const fromAddress = input.fromAddress ?? `mail@${fromDomain}`;
  const date = input.date ?? "2026-08-20T12:00:00.000Z";
  return {
    provider: "gmail",
    accountProof: "ema-15-account",
    messageId: `message-${input.nativeId}`,
    providerNativeId: input.nativeId,
    folder: "inbox",
    providerFolderName: "INBOX",
    from: {
      displayName: input.displayName ?? "Service",
      address: fromAddress,
      domain: fromDomain,
    },
    replyTo: null,
    subject: input.subject,
    date,
    authentication: {
      providerTrust: "trusted",
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      arc: "none",
    },
    textPreview: input.preview ?? input.subject,
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: {
      listId: input.listId ?? null,
      listUnsubscribe: input.unsubscribe ?? null,
      listUnsubscribePost: input.unsubscribe ? "List-Unsubscribe=One-Click" : null,
      oneClickHeaderSetUnambiguous: Boolean(input.unsubscribe),
    },
    threadContext: {
      isFirstContact: false,
      threadContinuityBroken: false,
      replyToChangedMidThread: false,
    },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: {
      fetchedAt: date,
      sizeBytes: 800,
      encoding: "plain",
      contentCoverage: "complete",
    },
  };
}

describe("EMA-15 Health identity aggregation", () => {
  it("presents one canonical footprint service with multiple authenticated evidence categories", () => {
    const snapshot = discoverDigitalAccountFootprint([
      envelope({
        nativeId: "relay-welcome-1",
        fromDomain: "privaterelay.appleid.com",
        fromAddress: "relay@privaterelay.appleid.com",
        displayName: "Apple Private Relay",
        subject: "Welcome - your account was created",
        date: "2026-08-18T09:00:00.000Z",
      }),
      envelope({
        nativeId: "relay-welcome-2",
        fromDomain: "privaterelay.appleid.com",
        fromAddress: "relay@privaterelay.appleid.com",
        displayName: "Apple Private Relay",
        subject: "Welcome to your account",
        date: "2026-08-19T09:00:00.000Z",
      }),
      envelope({
        nativeId: "relay-receipt-1",
        fromDomain: "privaterelay.appleid.com",
        fromAddress: "relay@privaterelay.appleid.com",
        displayName: "Apple Private Relay",
        subject: "Subscription receipt",
        date: "2026-08-20T09:00:00.000Z",
      }),
    ]);

    expect(snapshot.entries).toHaveLength(1);
    const entry = snapshot.entries[0] as unknown as {
      serviceDomain: string;
      messages: number;
      authenticatedMessages: number;
      evidence: Array<{ kind: string; messages: number; authenticatedMessages: number }>;
    };
    expect(entry.serviceDomain).toBe("privaterelay.appleid.com");
    expect(entry.messages).toBe(3);
    expect(entry.authenticatedMessages).toBe(3);
    expect(entry.evidence).toEqual(expect.arrayContaining([
      { kind: "account_welcome", messages: 2, authenticatedMessages: 2 },
      { kind: "receipt_subscription", messages: 1, authenticatedMessages: 1 },
    ]));
  });

  it("keeps same-name actionable subscriptions distinct while giving the consumer a privacy-safe differentiator", () => {
    const snapshot = analyzeInboxHealth([
      envelope({
        nativeId: "instagram-promotions-1",
        displayName: "Instagram",
        fromDomain: "mail.instagram.com",
        fromAddress: "updates@mail.instagram.com",
        listId: "promotions.instagram.test",
        unsubscribe: "https://mail.instagram.com/unsubscribe/promotions",
        subject: "Promotion one",
        date: "2026-08-10T10:00:00.000Z",
      }),
      envelope({
        nativeId: "instagram-promotions-2",
        displayName: "Instagram",
        fromDomain: "mail.instagram.com",
        fromAddress: "updates@mail.instagram.com",
        listId: "promotions.instagram.test",
        unsubscribe: "https://mail.instagram.com/unsubscribe/promotions",
        subject: "Promotion two",
        date: "2026-08-11T10:00:00.000Z",
      }),
      envelope({
        nativeId: "instagram-product-1",
        displayName: "Instagram",
        fromDomain: "mail.instagram.com",
        fromAddress: "updates@mail.instagram.com",
        listId: "product.instagram.test",
        unsubscribe: "https://mail.instagram.com/unsubscribe/product",
        subject: "Product update",
        date: "2026-08-12T10:00:00.000Z",
      }),
    ], { now: Date.parse("2026-08-20T12:00:00.000Z") });

    expect(snapshot.subscriptions).toHaveLength(2);
    expect(new Set(snapshot.subscriptions.map((item) => item.key)).size).toBe(2);
    expect(new Set(snapshot.subscriptions.map((item) => item.displayName))).toEqual(new Set(["Instagram"]));

    const presentation = snapshot.subscriptions as unknown as Array<{
      sameNameOrdinal?: number;
      sameNameTotal?: number;
    }>;
    expect(presentation.map((item) => item.sameNameTotal)).toEqual([2, 2]);
    expect(presentation.map((item) => item.sameNameOrdinal)).toEqual([1, 2]);
    expect(consumerProduct).toContain("sameNameTotal");
    expect(consumerProduct).toContain("sameNameOrdinal");
  });

  it("carries the selected canonical subscription identity through destructive cleanup so sibling lists sharing one sender cannot collide", () => {
    const first = envelope({
      nativeId: "instagram-list-a",
      displayName: "Instagram",
      fromDomain: "mail.instagram.com",
      fromAddress: "updates@mail.instagram.com",
      listId: "promotions.instagram.test",
      unsubscribe: "https://mail.instagram.com/unsubscribe/promotions",
      subject: "Promotion",
    });
    const sibling = envelope({
      nativeId: "instagram-list-b",
      displayName: "Instagram",
      fromDomain: "mail.instagram.com",
      fromAddress: "updates@mail.instagram.com",
      listId: "product.instagram.test",
      unsubscribe: "https://mail.instagram.com/unsubscribe/product",
      subject: "Product update",
    });
    const snapshot = analyzeInboxHealth([first, sibling]);
    expect(snapshot.subscriptions).toHaveLength(2);
    expect(snapshot.subscriptions[0]!.senderAddress).toBe(snapshot.subscriptions[1]!.senderAddress);
    expect(snapshot.subscriptions[0]!.senderDomain).toBe(snapshot.subscriptions[1]!.senderDomain);
    expect(snapshot.subscriptions[0]!.key).not.toBe(snapshot.subscriptions[1]!.key);

    const identityKey = (inboxHealthModule as unknown as Record<string, unknown>).subscriptionIdentityKey;
    expect.soft(identityKey).toBeTypeOf("function");
    if (typeof identityKey === "function") {
      expect(identityKey(first)).not.toBe(identityKey(sibling));
      expect(new Set(snapshot.subscriptions.map((item) => item.key))).toEqual(new Set([
        identityKey(first),
        identityKey(sibling),
      ]));
    }

    expect(cleanupController).toContain("subscriptionKey: group.key");
    expect(protectionRoutes).toContain("subscriptionKey");
    expect(healthWorker).toContain("subscriptionKey");
    expect(healthWorker).toContain("subscriptionIdentityKey");
  });
});
