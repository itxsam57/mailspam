import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { FixtureAdapter } from "../../server/src/adapters/fixtures/fixtureAdapter.js";
import type { CanonicalEnvelope, Provider } from "../../server/src/canonical/envelope.js";
import {
  evaluatePortableCore,
  MAX_PORTABLE_CORE_REQUEST_BYTES,
  PortableCoreContractError,
  scanMessageThroughPortableCore,
  type PortableCoreRequestV1,
} from "../../server/src/core/portableCore.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { annotateRelationshipHistory } from "../../server/src/engine/relationshipHistory.js";

const maliciousEml = readFileSync(
  join(import.meta.dirname, "../../fixtures/scam-corpus/credential_phishing/malicious-plain.eml"),
  "utf8",
);
const providers: Provider[] = ["gmail", "icloud", "outlook", "yahoo", "imap"];

async function envelope(provider: Provider): Promise<CanonicalEnvelope> {
  const adapter = new FixtureAdapter(provider, [{
    id: `${provider}-portable-core-vector`,
    rawEml: maliciousEml,
    folder: "inbox",
    providerFolderName: "INBOX",
    authenticationTrust: "trusted",
  }]);
  await adapter.connect(new AbortController().signal);
  const folder = (await adapter.listFolders(new AbortController().signal)).find((item) => item.normalized === "inbox")!;
  const page = await adapter.fetchPage(folder, null, 1, new AbortController().signal);
  await adapter.disconnect();
  const value = page.envelopes[0]!;
  annotateRelationshipHistory(value, undefined);
  return value;
}

function request(value: CanonicalEnvelope): PortableCoreRequestV1 {
  return {
    schemaVersion: 1,
    envelope: value,
    personalPolicy: {
      blockedSenders: [],
      blockedDomains: [],
      trustedSenders: [],
      approvedExceptions: [],
      unsubscribedActions: [],
      reportedCampaigns: [],
    },
    intelligence: { state: "verified", entries: [] },
  };
}

describe("versioned portable protection core contract", () => {
  it("preserves byte-for-byte decision parity across all five provider envelopes", async () => {
    for (const provider of providers) {
      const value = await envelope(provider);
      const policy = new InMemoryPersonalPolicyStore();
      const legacy = scanMessage(structuredClone(value), {
        personalPolicy: policy,
        threatFeed: { getVerifiedEntries: () => [] },
      });
      const portable = scanMessageThroughPortableCore(value, policy, []);
      expect(JSON.stringify(portable.scored)).toBe(JSON.stringify(legacy.scored));
      expect(portable.action).toBe(legacy.action);
      expect(portable.scored.verdict).not.toBe("safe");
    }
  });

  it("returns only decision data and never echoes the canonical envelope", async () => {
    const value = await envelope("gmail");
    const response = evaluatePortableCore(request(value));
    const serialized = JSON.stringify(response);
    expect(response.schemaVersion).toBe(1);
    expect(response.verdict).not.toBe("safe");
    // The version-1 response remains extensible by layer; structural consistency is now the twelfth provider-neutral decision layer.
    expect(response.layerResults).toHaveLength(12);
    expect(serialized).not.toContain(value.accountProof);
    expect(serialized).not.toContain(value.providerNativeId);
    expect(serialized).not.toContain(value.subject);
    expect(response).not.toHaveProperty("envelope");
  });

  it("preserves personal and signed-intelligence precedence", async () => {
    const value = await envelope("outlook");
    const blocked = request(value);
    blocked.personalPolicy.blockedDomains = [value.from.domain!];
    expect(evaluatePortableCore(blocked)).toMatchObject({
      verdict: "confirmed_threat",
      confirmedByRule: true,
      action: "auto_trash_allowed",
    });

    const unavailable = request(value);
    unavailable.intelligence = { state: "unavailable", entries: null };
    const result = evaluatePortableCore(unavailable);
    expect(result.layerResults.find((layer) => layer.layer === "global_intelligence")).toMatchObject({
      incomplete: true,
      blocksSafeVerdict: true,
    });
  });

  it("degrades oversized live-provider metadata to partial coverage instead of crashing the portable core", async () => {
    const value = await envelope("icloud");
    value.subject = "s".repeat(16_385);
    value.from.displayName = "d".repeat(4_097);
    value.authentication.rawHeader = "a".repeat(16_385);
    value.listHeaders.listUnsubscribe = `<https://example.test/${"u".repeat(16_385)}>`;
    const policy = new InMemoryPersonalPolicyStore();

    const result = scanMessageThroughPortableCore(value, policy, []);

    expect(result.envelope.parseStatus).toBe("partial");
    expect(result.envelope.parseNotes).toContain("Portable inspection coverage was reduced because provider data exceeded safety limits.");
    expect(result.envelope.subject.length).toBeLessThanOrEqual(16_384);
    expect(result.envelope.from.displayName?.length ?? 0).toBeLessThanOrEqual(4_096);
    expect(result.envelope.authentication.rawHeader).toBeUndefined();
    expect(result.envelope.listHeaders.listUnsubscribe).toBeNull();
    expect(result.scored.verdict).not.toBe("safe");
  });

  it("rejects version drift, unknown fields, raw thread references and oversized input before evaluation", async () => {
    const valid = request(await envelope("imap"));
    expect(() => evaluatePortableCore({ ...valid, schemaVersion: 2 })).toThrow(PortableCoreContractError);
    expect(() => evaluatePortableCore({ ...valid, credential: "must-not-enter-core" })).toThrow(/invalid/i);
    const rawThread = structuredClone(valid);
    rawThread.envelope.threadContext.pendingThreadReferences = { inReplyTo: "raw-message-id", references: [] };
    expect(() => evaluatePortableCore(rawThread)).toThrow(/invalid/i);

    const oversized = structuredClone(valid);
    oversized.envelope.textPreview = "x".repeat(MAX_PORTABLE_CORE_REQUEST_BYTES);
    try {
      evaluatePortableCore(oversized);
      throw new Error("oversized request unexpectedly passed");
    } catch (error) {
      expect(error).toBeInstanceOf(PortableCoreContractError);
      expect((error as PortableCoreContractError).code).toBe("request_too_large");
    }
  });
});
