import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { campaignFingerprint } from "../../server/src/community/fingerprint.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import {
  collectCommunityWarningQuarantineIds,
  collectDurableAutoTrashIds,
  isCommunityWarningQuarantineResult,
  isDurableAutoTrashResult,
} from "../../server/src/workflows/durableProtection.js";
import {
  familyThreatSnapshotToFeedEntries,
  mergeVerifiedAndFamilyIntelligence,
} from "../../server/src/platform/familyThreatFeedAdapter.js";
import type { FamilyThreatSnapshot } from "../../server/src/platform/accountFamilyTypes.js";

function envelope(): CanonicalEnvelope {
  return {
    provider: "icloud",
    accountProof: "proof",
    messageId: "family-message",
    providerNativeId: "family-native-1",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Normal sender", address: "sender@example.test", domain: "example.test" },
    replyTo: null,
    subject: "Routine project update",
    date: new Date(0).toISOString(),
    authentication: { providerTrust: "trusted", spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview: "A normal message that contains no threat content by itself.",
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: false, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 500, encoding: "plain", contentCoverage: "complete" },
  };
}

function familySnapshot(input: CanonicalEnvelope, status: "warning" | "confirmed"): FamilyThreatSnapshot {
  return {
    familyCircleId: "family_test-circle",
    accountId: "acct_test-account",
    entries: [{ campaignFingerprint: campaignFingerprint(input), status }],
  };
}

describe("Family Shield portable intelligence", () => {
  it("turns a family warning into Review and reversible Spam/Junk disposition even for otherwise Safe mail", () => {
    const input = envelope();
    const entries = familyThreatSnapshotToFeedEntries(familySnapshot(input, "warning"));
    const result = scanMessage(input, {
      personalPolicy: new InMemoryPersonalPolicyStore(),
      threatFeed: { getVerifiedEntries: () => entries },
    });
    expect(result.scored.evidence).toContainEqual(expect.objectContaining({ code: "FAMILY_WARNING_MATCH", scoreContribution: 3 }));
    expect(result.scored.evidence.some((item) => item.code === "GLOBAL_WARNING_MATCH")).toBe(false);
    expect(result.scored.verdict).toBe("review");
    expect(isCommunityWarningQuarantineResult(result)).toBe(true);
    const ids = new Set<string>();
    collectCommunityWarningQuarantineIds([result], ids);
    expect([...ids]).toEqual(["family-native-1"]);
  });

  it("turns a family confirmed campaign into Confirmed Threat and durable Trash without globalizing it", () => {
    const input = envelope();
    const entries = familyThreatSnapshotToFeedEntries(familySnapshot(input, "confirmed"));
    const result = scanMessage(input, {
      personalPolicy: new InMemoryPersonalPolicyStore(),
      threatFeed: { getVerifiedEntries: () => entries },
    });
    expect(result.scored.evidence).toContainEqual(expect.objectContaining({ code: "FAMILY_CONFIRMED_MATCH", scoreContribution: 10 }));
    expect(result.scored.evidence.some((item) => item.code === "GLOBAL_CONFIRMED_MATCH")).toBe(false);
    expect(result.scored.verdict).toBe("confirmed_threat");
    expect(isDurableAutoTrashResult(result)).toBe(true);
    const ids = new Set<string>();
    collectDurableAutoTrashIds([result], ids);
    expect([...ids]).toEqual(["family-native-1"]);
  });

  it("uses only campaign fingerprints in Family Shield feed entries", () => {
    const input = envelope();
    const [entry] = familyThreatSnapshotToFeedEntries(familySnapshot(input, "warning"));
    expect(entry).toMatchObject({ type: "campaign", value: campaignFingerprint(input), confirmedThreat: false });
    const serialized = JSON.stringify(entry);
    for (const forbidden of [input.subject, input.from.address!, input.providerNativeId!, input.textPreview!]) {
      expect(serialized).not.toContain(forbidden);
    }
  });

  it("never lets private family availability hide a failed global signed feed", () => {
    const input = envelope();
    expect(mergeVerifiedAndFamilyIntelligence(null, familySnapshot(input, "confirmed"))).toBeNull();
  });

  it("merges family state per account without mutating the verified global entry array", () => {
    const input = envelope();
    const global = [{ type: "campaign" as const, value: "f".repeat(64), confirmedThreat: false, ruleId: "community:warning" }];
    const merged = mergeVerifiedAndFamilyIntelligence(global, familySnapshot(input, "warning"));
    expect(global).toHaveLength(1);
    expect(merged).toHaveLength(2);
    expect(merged?.[1]).toMatchObject({ value: campaignFingerprint(input) });
  });
});
