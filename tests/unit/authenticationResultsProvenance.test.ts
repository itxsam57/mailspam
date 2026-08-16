import { describe, expect, it } from "vitest";
import type { AuthenticationSignals, CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { FixtureAdapter } from "../../server/src/adapters/fixtures/fixtureAdapter.js";
import {
  authenticationPassed,
  authenticationResultsTrusted,
  authenticatedSenderIdentityDomains,
  verifiedRelayOriginDomains,
} from "../../server/src/engine/identitySignals.js";
import { transportAuthLayer } from "../../server/src/engine/layers/transportAuth.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";
import {
  annotateRelationshipHistory,
  createRelationshipObservation,
  relationshipIdentityKey,
  type RelationshipHistoryWorkerSnapshot,
} from "../../server/src/engine/relationshipHistory.js";

function envelope(authentication: AuthenticationSignals): CanonicalEnvelope {
  return {
    provider: "outlook",
    accountProof: "proof",
    messageId: "message-id",
    providerNativeId: "native-id",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: {
      displayName: "Cobalt Bank Security",
      address: "security@alerts.cobalt-bank.example",
      domain: "alerts.cobalt-bank.example",
    },
    replyTo: null,
    subject: "Cobalt Bank monthly information",
    date: new Date(0).toISOString(),
    authentication,
    textPreview: "Account information and service updates are available in your secure dashboard. ".repeat(3),
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: {
      fetchedAt: new Date(0).toISOString(),
      sizeBytes: 1000,
      encoding: "plain",
      contentCoverage: "complete",
    },
  };
}

const deps = () => ({
  personalPolicy: new InMemoryPersonalPolicyStore(),
  threatFeed: { getVerifiedEntries: () => [] },
});

function establishedSnapshot(address: string): RelationshipHistoryWorkerSnapshot {
  const indexKey = Buffer.alloc(32, 7).toString("base64");
  const senderKey = relationshipIdentityKey(indexKey, "sender", address);
  const now = Date.now();
  return {
    indexKey,
    seenMessageKeys: new Set(),
    records: {
      [senderKey]: {
        messagesSeen: 3,
        authenticatedMessages: 2,
        safeMessages: 2,
        reviewMessages: 0,
        highRiskMessages: 0,
        confirmedThreatMessages: 0,
        unknownMessages: 1,
        firstObservedAt: now - 3_000,
        lastObservedAt: now - 1_000,
        lastAuthenticatedAt: now - 2_000,
        folderCounts: { inbox: 3 },
        replyToCounts: {},
      },
    },
  };
}

describe("Authentication-Results provenance", () => {
  it("does not authenticate RFC5322.From from an unproven DMARC pass", () => {
    const message = envelope({
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      arc: "pass",
      providerTrust: "unknown",
      rawHeader: "attacker.example; dmarc=pass header.from=cobalt-bank.example; spf=pass smtp.mailfrom=bounce@cobalt-bank.example; dkim=pass header.d=cobalt-bank.example",
    });

    expect(authenticationResultsTrusted(message)).toBe(false);
    expect(authenticationPassed(message)).toBe(false);
    expect(authenticatedSenderIdentityDomains(message)).toEqual([]);
  });

  it("does not let a forged relay-shaped local part create a verified origin from untrusted results", () => {
    const message = envelope({
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      arc: "pass",
      providerTrust: "unknown",
      rawHeader: "forged.example; dmarc=pass header.from=privaterelay.appleid.com; dkim=pass header.d=privaterelay.appleid.com",
    });
    message.from = {
      displayName: "Cobalt Bank Security",
      address: "notice_at_alerts_cobalt-bank_example_random9@privaterelay.appleid.com",
      domain: "privaterelay.appleid.com",
    };

    expect(authenticationResultsTrusted(message)).toBe(false);
    expect(authenticationPassed(message)).toBe(false);
    expect(verifiedRelayOriginDomains(message)).toEqual([]);
    expect(authenticatedSenderIdentityDomains(message)).toEqual([]);
  });

  it("treats missing provenance as untrusted rather than preserving legacy trust", () => {
    const message = envelope({
      spf: "unknown",
      dkim: "pass",
      dmarc: "unknown",
      arc: "none",
      rawHeader: "forged.example; dkim=pass header.d=mailer.cobalt-bank.example",
    });

    expect(authenticationResultsTrusted(message)).toBe(false);
    expect(authenticationPassed(message)).toBe(false);
  });

  it("does not let untrusted aligned SPF/DKIM unlock bounded-partial Safe", () => {
    const message = envelope({
      spf: "pass",
      dkim: "pass",
      dmarc: "none",
      arc: "none",
      providerTrust: "unknown",
      rawHeader: "forged.example; spf=pass smtp.mailfrom=bounce@mailer.cobalt-bank.example; dkim=pass header.d=mailer.cobalt-bank.example",
    });
    message.parseStatus = "partial";
    message.parseNotes = ["Readable text was bounded to 24576 bytes."];
    message.diagnostics.contentCoverage = "bounded_sufficient";

    expect(scanMessage(message, deps()).scored.verdict).toBe("unknown");
  });

  it("does not score untrusted authentication failures as threat evidence", () => {
    const message = envelope({
      spf: "fail",
      dkim: "fail",
      dmarc: "fail",
      arc: "fail",
      providerTrust: "unknown",
      rawHeader: "forged.example; dmarc=fail; spf=fail; dkim=fail",
    });

    const result = transportAuthLayer(message);
    expect(result.incomplete).toBe(true);
    expect(result.evidence).toEqual([]);
    expect(result.incompleteReason).toMatch(/provenance/i);
  });

  it("still uses failures after provenance is explicitly trusted", () => {
    const message = envelope({
      spf: "fail",
      dkim: "fail",
      dmarc: "fail",
      arc: "none",
      providerTrust: "trusted",
      rawHeader: "mx.receiver.example; dmarc=fail; spf=fail; dkim=fail",
    });

    expect(transportAuthLayer(message).evidence.map((item) => item.code)).toEqual([
      "DMARC_FAIL",
      "SPF_DKIM_BOTH_FAIL",
    ]);
  });

  it("still authenticates an aligned author after provenance is explicitly trusted", () => {
    const message = envelope({
      spf: "unknown",
      dkim: "pass",
      dmarc: "unknown",
      arc: "none",
      providerTrust: "trusted",
      rawHeader: "mx.receiver.example; dkim=pass header.d=mailer.cobalt-bank.example",
    });

    expect(authenticationResultsTrusted(message)).toBe(true);
    expect(authenticationPassed(message)).toBe(true);
    expect(authenticatedSenderIdentityDomains(message)).toEqual(["cobalt-bank.example"]);
  });

  it("does not let ARC pass bypass the provenance or author-alignment boundary", () => {
    const message = envelope({
      spf: "fail",
      dkim: "fail",
      dmarc: "fail",
      arc: "pass",
      providerTrust: "unknown",
      rawHeader: "forged.example; arc=pass; dmarc=fail",
    });

    expect(authenticationPassed(message)).toBe(false);
    expect(transportAuthLayer(message).evidence).toEqual([]);
  });

  it("does not learn authenticated relationship history from untrusted results", () => {
    const message = envelope({
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      arc: "none",
      providerTrust: "unknown",
      rawHeader: "forged.example; dmarc=pass header.from=cobalt-bank.example",
    });
    const snapshot = establishedSnapshot(message.from.address!);

    const observation = createRelationshipObservation(message, "safe", snapshot, 10);
    expect(observation?.authenticated).toBe(false);
  });

  it("does not create a relationship authentication downgrade from an untrusted failure", () => {
    const message = envelope({
      spf: "fail",
      dkim: "fail",
      dmarc: "fail",
      arc: "none",
      providerTrust: "unknown",
      rawHeader: "forged.example; dmarc=fail; spf=fail; dkim=fail",
    });
    const snapshot = establishedSnapshot(message.from.address!);

    annotateRelationshipHistory(message, snapshot);
    expect(message.threadContext.hasEstablishedSenderHistory).toBe(true);
    expect(message.threadContext.relationshipAuthenticationDowngrade).toBe(false);

    message.authentication.providerTrust = "trusted";
    annotateRelationshipHistory(message, snapshot);
    expect(message.threadContext.relationshipAuthenticationDowngrade).toBe(true);
  });

  it("requires fixtures to opt into simulated provider authentication trust per message", async () => {
    const raw = [
      "From: Cobalt Bank <security@alerts.cobalt-bank.example>",
      "Subject: Account information",
      "Authentication-Results: mx.receiver.example; dmarc=pass header.from=cobalt-bank.example",
      "Message-ID: <auth-provenance@example.test>",
      "Date: Thu, 01 Jan 1970 00:00:00 +0000",
      "Content-Type: text/plain; charset=utf-8",
      "",
      "Routine account information from the sender.",
    ].join("\r\n");
    const adapter = new FixtureAdapter("gmail", [
      { id: "unknown", rawEml: raw, folder: "inbox", providerFolderName: "INBOX" },
      { id: "trusted", rawEml: raw, folder: "inbox", providerFolderName: "INBOX", authenticationTrust: "trusted" },
    ]);
    const controller = new AbortController();
    await adapter.connect(controller.signal);
    const [folder] = await adapter.listFolders(controller.signal);
    const page = await adapter.fetchPage(folder!, null, 10, controller.signal);

    expect(page.envelopes).toHaveLength(2);
    expect(page.envelopes[0]!.authentication.providerTrust).toBe("unknown");
    expect(authenticationPassed(page.envelopes[0]!)).toBe(false);
    expect(page.envelopes[1]!.authentication.providerTrust).toBe("trusted");
    expect(authenticationPassed(page.envelopes[1]!)).toBe(true);
  });
});
