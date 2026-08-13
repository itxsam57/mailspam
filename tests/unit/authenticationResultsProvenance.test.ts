import { describe, expect, it } from "vitest";
import type { AuthenticationSignals, CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { FixtureAdapter } from "../../server/src/adapters/fixtures/fixtureAdapter.js";
import {
  authenticationPassed,
  authenticationResultsTrusted,
  authenticatedSenderIdentityDomains,
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
      rawHeader: "forged.example; dmarc=pass header.from=cobalt-bank.example",
    });

    expect(authenticationResultsTrusted(message)).toBe(false);
    expect(authenticatedSenderIdentityDomains(message)).toEqual([]);
    expect(authenticationPassed(message)).toBe(false);
  });

  it("treats missing provenance as untrusted rather than preserving legacy trust", () => {
    const message = envelope({
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      arc: "none",
      rawHeader: "forged.example; dmarc=pass header.from=cobalt-bank.example",
    });

    expect(authenticationResultsTrusted(message)).toBe(false);
    expect(authenticatedSenderIdentityDomains(message)).toEqual([]);
    expect(authenticationPassed(message)).toBe(false);
  });

  it("does not let untrusted aligned SPF/DKIM unlock bounded-partial Safe", () => {
    const message = envelope({
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      arc: "none",
      providerTrust: "unknown",
      rawHeader: "forged.example; dmarc=pass header.from=cobalt-bank.example",
    });
    message.parseStatus = "partial";
    message.diagnostics.contentCoverage = "bounded_sufficient";

    const result = scanMessage(message, deps());
    expect(result.scored.verdict).toBe("unknown");
  });

  it("does not score untrusted authentication failures as threat evidence", () => {
    const message = envelope({
      spf: "fail",
      dkim: "fail",
      dmarc: "fail",
      arc: "none",
      providerTrust: "unknown",
      rawHeader: "forged.example; dmarc=fail; spf=fail; dkim=fail",
    });

    const result = transportAuthLayer(message);
    expect(result.evidence).toEqual([]);
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

    const result = transportAuthLayer(message);
    expect(result.evidence.some((item) => item.code === "DMARC_FAIL" && item.scoreContribution > 0)).toBe(true);
    expect(result.evidence.some((item) => item.code === "SPF_FAIL" && item.scoreContribution > 0)).toBe(true);
    expect(result.evidence.some((item) => item.code === "DKIM_FAIL" && item.scoreContribution > 0)).toBe(true);
  });

  it("still authenticates an aligned author after provenance is explicitly trusted", () => {
    const message = envelope({
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      arc: "none",
      providerTrust: "trusted",
      rawHeader: "mx.receiver.example; dmarc=pass header.from=cobalt-bank.example; dkim=pass header.d=cobalt-bank.example; spf=pass smtp.mailfrom=cobalt-bank.example",
    });
    message.from.domain = "cobalt-bank.example";

    expect(authenticationResultsTrusted(message)).toBe(true);
    expect(authenticatedSenderIdentityDomains(message)).toContain("cobalt-bank.example");
    expect(authenticationPassed(message)).toBe(true);
  });

  it("does not let ARC pass bypass the provenance or author-alignment boundary", () => {
    const message = envelope({
      spf: "unknown",
      dkim: "unknown",
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
      "",
      "Account information is available in your dashboard.",
    ].join("\r\n");

    const untrusted = new FixtureAdapter("outlook", [{
      id: "untrusted",
      rawEml: raw,
      folder: "inbox",
      providerFolderName: "INBOX",
    }]);
    await untrusted.connect(new AbortController().signal);
    const untrustedFolder = (await untrusted.listFolders(new AbortController().signal)).find((folder) => folder.normalized === "inbox")!;
    const untrustedEnvelope = (await untrusted.fetchPage(untrustedFolder, null, 10, new AbortController().signal)).envelopes[0]!;
    expect(untrustedEnvelope.authentication.providerTrust).toBe("unknown");
    expect(authenticationPassed(untrustedEnvelope)).toBe(false);

    const trusted = new FixtureAdapter("outlook", [{
      id: "trusted",
      rawEml: raw,
      folder: "inbox",
      providerFolderName: "INBOX",
      authenticationTrust: "trusted",
    }]);
    await trusted.connect(new AbortController().signal);
    const trustedFolder = (await trusted.listFolders(new AbortController().signal)).find((folder) => folder.normalized === "inbox")!;
    const trustedEnvelope = (await trusted.fetchPage(trustedFolder, null, 10, new AbortController().signal)).envelopes[0]!;
    expect(trustedEnvelope.authentication.providerTrust).toBe("trusted");
  });
});
