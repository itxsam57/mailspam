import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import {
  annotateRelationshipHistory,
  RELATIONSHIP_FULL_CONFIDENCE_AGE_MS,
  RELATIONSHIP_ZERO_CONFIDENCE_AGE_MS,
  relationshipIdentityKey,
  relationshipPositiveConfidence,
  type RelationshipHistoryWorkerSnapshot,
  type RelationshipProfile,
} from "../../server/src/engine/relationshipHistory.js";
import { relationshipContextLayer } from "../../server/src/engine/layers/relationshipContext.js";
import { messageIntentLayer } from "../../server/src/engine/layers/messageIntent.js";

const TEST_NOW = Date.parse("2026-08-13T00:00:00.000Z");
const RECENT_HISTORY = TEST_NOW - 24 * 60 * 60 * 1_000;

function profile(overrides: Partial<RelationshipProfile> = {}): RelationshipProfile {
  return {
    messagesSeen: 4,
    authenticatedMessages: 4,
    safeMessages: 4,
    reviewMessages: 0,
    highRiskMessages: 0,
    confirmedThreatMessages: 0,
    unknownMessages: 0,
    firstObservedAt: RECENT_HISTORY - 10_000,
    lastObservedAt: RECENT_HISTORY,
    lastAuthenticatedAt: RECENT_HISTORY,
    folderCounts: { inbox: 4 },
    replyToCounts: {},
    ...overrides,
  };
}

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  return {
    provider: "imap",
    accountProof: "proof",
    messageId: "<current@example.com>",
    providerNativeId: "current",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Known Sender", address: "known@example.com", domain: "example.com" },
    replyTo: null,
    subject: "Routine account update",
    date: new Date(TEST_NOW).toISOString(),
    authentication: { providerTrust: "trusted", spf: "pass", dkim: "pass", dmarc: "pass", arc: "unknown" },
    textPreview: "This is a routine readable account message with no unusual request or pressure.",
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: {
      fetchedAt: new Date(TEST_NOW).toISOString(),
      sizeBytes: 500,
      encoding: "plain",
      contentCoverage: "complete",
    },
    ...overrides,
  };
}

function snapshotFor(
  sender: string,
  senderProfile: RelationshipProfile,
  indexKey = Buffer.alloc(32, 12).toString("base64"),
  seenMessageKeys: string[] = [],
): RelationshipHistoryWorkerSnapshot {
  const senderKey = relationshipIdentityKey(indexKey, "sender", sender);
  return {
    indexKey,
    records: { [senderKey]: senderProfile },
    seenMessageKeys: new Set(seenMessageKeys),
  };
}

function messageKey(indexKey: string, provider: CanonicalEnvelope["provider"], messageId: string): string {
  return relationshipIdentityKey(indexKey, "message", `${provider}\0${messageId}`);
}

describe("durable relationship context", () => {
  it("marks conservative established history without weakening the canonical first-contact flag", () => {
    const current = envelope();
    annotateRelationshipHistory(current, snapshotFor("known@example.com", profile()));

    expect(current.threadContext.hasEstablishedSenderHistory).toBe(true);
    expect(current.threadContext.relationshipPriorMessages).toBe(4);
    expect(current.threadContext.isFirstContact).toBe(true);

    const result = relationshipContextLayer(current);
    expect(result.evidence.some((item) => item.code === "ESTABLISHED_LOCAL_SENDER_HISTORY" && item.scoreContribution === 0)).toBe(true);
    expect(result.evidence.some((item) => item.code === "FIRST_CONTACT")).toBe(false);
  });

  it("decays only the positive familiarity reward after prolonged inactivity", () => {
    const fresh = profile({
      lastObservedAt: TEST_NOW - RELATIONSHIP_FULL_CONFIDENCE_AGE_MS,
      lastAuthenticatedAt: TEST_NOW - RELATIONSHIP_FULL_CONFIDENCE_AGE_MS,
    });
    const stale = profile({
      lastObservedAt: TEST_NOW - RELATIONSHIP_ZERO_CONFIDENCE_AGE_MS - 1,
      lastAuthenticatedAt: TEST_NOW - RELATIONSHIP_ZERO_CONFIDENCE_AGE_MS - 1,
    });

    expect(relationshipPositiveConfidence(fresh, TEST_NOW)).toBe(1);
    expect(relationshipPositiveConfidence(stale, TEST_NOW)).toBe(0);

    const current = envelope();
    annotateRelationshipHistory(current, snapshotFor("known@example.com", stale));
    expect(current.threadContext.hasEstablishedSenderHistory).toBe(false);
    expect(relationshipContextLayer(current).evidence.some((item) => item.code === "FIRST_CONTACT")).toBe(true);
  });

  it("retains authentication-downgrade risk even after positive familiarity has decayed", () => {
    const stale = profile({
      lastObservedAt: TEST_NOW - RELATIONSHIP_ZERO_CONFIDENCE_AGE_MS - 1,
      lastAuthenticatedAt: TEST_NOW - RELATIONSHIP_ZERO_CONFIDENCE_AGE_MS - 1,
    });
    const current = envelope({
      authentication: { providerTrust: "trusted", spf: "fail", dkim: "fail", dmarc: "fail", arc: "unknown" },
    });
    annotateRelationshipHistory(current, snapshotFor("known@example.com", stale));
    const result = relationshipContextLayer(current);

    expect(current.threadContext.hasEstablishedSenderHistory).toBe(false);
    expect(current.threadContext.relationshipAuthenticationDowngrade).toBe(true);
    expect(result.evidence.some((item) => item.code === "RELATIONSHIP_AUTH_DOWNGRADE" && item.scoreContribution > 0)).toBe(true);
  });

  it("detects an explicit authentication downgrade after established authenticated history", () => {
    const current = envelope({
      authentication: { providerTrust: "trusted", spf: "fail", dkim: "fail", dmarc: "fail", arc: "unknown" },
    });
    annotateRelationshipHistory(current, snapshotFor("known@example.com", profile()));
    const result = relationshipContextLayer(current);

    expect(current.threadContext.relationshipAuthenticationDowngrade).toBe(true);
    expect(result.evidence.some((item) => item.code === "RELATIONSHIP_AUTH_DOWNGRADE" && item.scoreContribution > 0)).toBe(true);
  });

  it("detects a change from a previously stable non-empty Reply-To destination", () => {
    const indexKey = Buffer.alloc(32, 13).toString("base64");
    const historicalReplyTo = relationshipIdentityKey(indexKey, "reply-to", "reply@known.example");
    const senderProfile = profile({ replyToCounts: { [historicalReplyTo]: 3 } });
    const current = envelope({
      replyTo: { displayName: null, address: "redirect@different.example", domain: "different.example" },
    });
    annotateRelationshipHistory(current, snapshotFor("known@example.com", senderProfile, indexKey));
    const result = relationshipContextLayer(current);

    expect(current.threadContext.replyToChangedFromRelationshipHistory).toBe(true);
    expect(result.evidence.some((item) => item.code === "RELATIONSHIP_REPLY_TO_CHANGE" && item.scoreContribution > 0)).toBe(true);
  });

  it("upgrades a stable Reply-To change to the specific mid-thread signal when a local parent is known", () => {
    const indexKey = Buffer.alloc(32, 21).toString("base64");
    const historicalReplyTo = relationshipIdentityKey(indexKey, "reply-to", "reply@known.example");
    const parentId = "<parent@example.com>";
    const current = envelope({
      replyTo: { displayName: null, address: "redirect@different.example", domain: "different.example" },
      threadContext: {
        isFirstContact: true,
        threadContinuityBroken: false,
        replyToChangedMidThread: false,
        pendingThreadReferences: {
          inReplyTo: parentId,
          references: ["<root@example.com>", parentId],
        },
      },
    });
    const snapshot = snapshotFor(
      "known@example.com",
      profile({ replyToCounts: { [historicalReplyTo]: 3 } }),
      indexKey,
      [messageKey(indexKey, "imap", parentId)],
    );

    annotateRelationshipHistory(current, snapshot);
    const result = relationshipContextLayer(current);

    expect(current.threadContext.pendingThreadReferences).toBeUndefined();
    expect(current.threadContext.replyToChangedMidThread).toBe(true);
    expect(current.threadContext.replyToChangedFromRelationshipHistory).toBe(false);
    expect(result.evidence.some((item) => item.code === "REPLY_TO_CHANGED_MID_THREAD" && item.scoreContribution === 4)).toBe(true);
    expect(result.evidence.some((item) => item.code === "RELATIONSHIP_REPLY_TO_CHANGE")).toBe(false);
  });

  it("marks a proven local parent/reference-chain contradiction without guessing from a bare Re subject", () => {
    const indexKey = Buffer.alloc(32, 22).toString("base64");
    const parentId = "<known-parent@example.com>";
    const current = envelope({
      subject: "Re: routine account update",
      threadContext: {
        isFirstContact: true,
        threadContinuityBroken: false,
        replyToChangedMidThread: false,
        pendingThreadReferences: {
          inReplyTo: parentId,
          references: ["<different-parent@example.com>"],
        },
      },
    });
    const snapshot = snapshotFor(
      "known@example.com",
      profile(),
      indexKey,
      [messageKey(indexKey, "imap", parentId)],
    );

    annotateRelationshipHistory(current, snapshot);
    const result = relationshipContextLayer(current);

    expect(current.threadContext.pendingThreadReferences).toBeUndefined();
    expect(current.threadContext.threadContinuityBroken).toBe(true);
    expect(result.evidence.some((item) => item.code === "THREAD_CONTINUITY_BROKEN" && item.scoreContribution === 3)).toBe(true);
  });

  it("does not manufacture continuity risk when an RFC parent is not already known locally", () => {
    const current = envelope({
      subject: "Re: routine account update",
      threadContext: {
        isFirstContact: true,
        threadContinuityBroken: false,
        replyToChangedMidThread: false,
        pendingThreadReferences: {
          inReplyTo: "<unknown-parent@example.com>",
          references: ["<another-unknown@example.com>"],
        },
      },
    });

    annotateRelationshipHistory(current, snapshotFor("known@example.com", profile()));

    expect(current.threadContext.pendingThreadReferences).toBeUndefined();
    expect(current.threadContext.threadContinuityBroken).toBe(false);
    expect(current.threadContext.replyToChangedMidThread).toBe(false);
  });

  it("deletes transient raw thread identifiers even when relationship history is unavailable", () => {
    const current = envelope({
      threadContext: {
        isFirstContact: true,
        threadContinuityBroken: false,
        replyToChangedMidThread: false,
        pendingThreadReferences: {
          inReplyTo: "<private-parent@example.com>",
          references: ["<private-root@example.com>"],
        },
      },
    });

    annotateRelationshipHistory(current, undefined);

    expect(current.threadContext.pendingThreadReferences).toBeUndefined();
    expect(JSON.stringify(current)).not.toContain("private-parent@example.com");
    expect(JSON.stringify(current)).not.toContain("private-root@example.com");
  });

  it("adds risk for a sender whose prior local history is predominantly suspicious", () => {
    const current = envelope();
    annotateRelationshipHistory(current, snapshotFor("known@example.com", profile({
      messagesSeen: 4,
      authenticatedMessages: 1,
      safeMessages: 0,
      reviewMessages: 2,
      highRiskMessages: 1,
    })));
    const result = relationshipContextLayer(current);

    expect(current.threadContext.hasEstablishedSenderHistory).toBe(false);
    expect(result.evidence.some((item) => item.code === "REPEATED_SUSPICIOUS_RELATIONSHIP_HISTORY" && item.scoreContribution > 0)).toBe(true);
  });

  it("does not suppress high-confidence first-contact adult-campaign rules for an established sender", () => {
    const current = envelope({
      replyTo: { displayName: null, address: "reply@unrelated-campaign.example", domain: "unrelated-campaign.example" },
      subject: "Join our exclusive adult community",
      textPreview: "Join our exclusive adult community and view private photos.",
      links: [{
        visibleText: "Join now",
        rawUrl: "https://unrelated-campaign.example/join",
        normalizedUrl: "https://unrelated-campaign.example/join",
        claimedBrand: null,
        brandDomainMismatch: null,
      }],
    });
    annotateRelationshipHistory(current, snapshotFor("known@example.com", profile()));

    expect(current.threadContext.hasEstablishedSenderHistory).toBe(true);
    expect(current.threadContext.isFirstContact).toBe(true);
    const intent = messageIntentLayer(current);
    expect(intent.evidence.some((item) => item.code === "UNSOLICITED_ADULT_SITE_CAMPAIGN")).toBe(true);
  });
});
