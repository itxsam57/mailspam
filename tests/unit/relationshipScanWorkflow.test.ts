import { describe, expect, it } from "vitest";
import { FixtureAdapter, type FixtureMessage } from "../../server/src/adapters/fixtures/fixtureAdapter.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { InMemoryRelationshipHistoryRepository } from "../../server/src/api/relationshipHistoryPersistence.js";
import { quickScan } from "../../server/src/workflows/scanWorkflows.js";
import { publicScanProgress } from "../../server/src/api/scanStream.js";

const ACCOUNT_KEY = "c".repeat(64);

function message(): FixtureMessage {
  return {
    id: "relationship-message-1",
    folder: "inbox",
    providerFolderName: "INBOX",
    rawEml: [
      "From: Relationship Sender <relationship.sender@example.com>",
      "To: user@example.com",
      "Subject: Routine relationship update",
      "Message-ID: <relationship-message-1@example.com>",
      "Date: Tue, 4 Aug 2026 10:00:00 +0000",
      "Authentication-Results: mx.example; dkim=pass; spf=pass; dmarc=pass",
      "Content-Type: text/plain; charset=utf-8",
      "",
      "This is a routine authenticated message with enough readable content and no unusual request.",
    ].join("\r\n"),
  };
}

async function run(repository: InMemoryRelationshipHistoryRepository) {
  const events = [];
  const adapter = new FixtureAdapter("gmail", [message()]);
  const personalPolicy = new InMemoryPersonalPolicyStore();
  for await (const progress of quickScan(
    adapter,
    {
      personalPolicy,
      threatFeed: { getVerifiedEntries: () => [] },
      relationshipHistory: repository.workerSnapshot(ACCOUNT_KEY),
    },
    new AbortController().signal,
    10,
    10,
  )) {
    events.push(progress);
  }
  return events;
}

describe("relationship-aware scan workflow", () => {
  it("emits HMAC-only server observations and does not expose them through public scan progress", async () => {
    const repository = new InMemoryRelationshipHistoryRepository(Buffer.alloc(32, 14));
    const events = await run(repository);
    const progress = events.at(-1)!;

    expect(progress.relationshipObservations).toHaveLength(1);
    const serializedObservation = JSON.stringify(progress.relationshipObservations[0]);
    expect(serializedObservation).not.toContain("relationship.sender@example.com");
    expect(serializedObservation).not.toContain("relationship-message-1@example.com");
    expect(progress.relationshipObservations[0]?.senderKey).toMatch(/^[a-f0-9]{64}$/);
    expect(progress.relationshipObservations[0]?.messageKey).toMatch(/^[a-f0-9]{64}$/);

    const publicValue = publicScanProgress(progress);
    const browserJson = JSON.stringify(publicValue);
    expect(browserJson).not.toContain("relationshipObservations");
    expect(browserJson).not.toContain(progress.relationshipObservations[0]!.senderKey);
    expect(browserJson).not.toContain(progress.relationshipObservations[0]!.messageKey);
  });

  it("does not emit a second observation for a message already committed to relationship history", async () => {
    const repository = new InMemoryRelationshipHistoryRepository(Buffer.alloc(32, 15));
    const first = await run(repository);
    repository.merge(ACCOUNT_KEY, first.flatMap((progress) => progress.relationshipObservations));

    const second = await run(repository);
    expect(second.flatMap((progress) => progress.relationshipObservations)).toHaveLength(0);
    expect(repository.workerSnapshot(ACCOUNT_KEY).seenMessageKeys.size).toBe(1);
  });
});
