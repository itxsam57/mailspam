import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { FixtureAdapter, type FixtureMessage } from "../../server/src/adapters/fixtures/fixtureAdapter.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { createStoppableScan, quickScan } from "../../server/src/workflows/scanWorkflows.js";
import { publicScanProgress } from "../../server/src/api/scanStream.js";

const corpus = join(import.meta.dirname, "../../fixtures/scam-corpus");
const deps = {
  personalPolicy: new InMemoryPersonalPolicyStore(),
  threatFeed: { getVerifiedEntries: () => [] },
};

function load(path: string): string {
  return readFileSync(join(corpus, path), "utf8");
}

describe("scan diagnostic summaries", () => {
  it("includes Safe and suspicious messages without bodies, links, credentials, or attachment content", async () => {
    const messages: FixtureMessage[] = [
      { id: "safe", rawEml: load("brand_impersonation/legit-plain.eml"), folder: "inbox", providerFolderName: "INBOX" },
      { id: "bad", rawEml: load("brand_impersonation/malicious-plain.eml"), folder: "inbox", providerFolderName: "INBOX" },
    ];
    const adapter = new FixtureAdapter("gmail", messages);
    const { signal } = createStoppableScan();

    const events = [];
    for await (const progress of quickScan(adapter, deps, signal)) events.push(progress);
    const final = events[0]!;

    expect(final.diagnosticSummaries).toHaveLength(2);
    expect(final.diagnosticSummaries.some((item) => item.verdict === "safe")).toBe(true);
    expect(final.diagnosticSummaries.some((item) => item.verdict !== "safe")).toBe(true);

    for (const item of final.diagnosticSummaries) {
      expect(item).toEqual(expect.objectContaining({
        subject: expect.any(String),
        folder: "INBOX",
        score: expect.any(Number),
        parseStatus: expect.any(String),
        parseNotes: expect.any(Array),
        evidenceCodes: expect.any(Array),
      }));
      expect(item).not.toHaveProperty("textPreview");
      expect(item).not.toHaveProperty("htmlSignals");
      expect(item).not.toHaveProperty("links");
      expect(item).not.toHaveProperty("attachments");
      expect(item).not.toHaveProperty("providerNativeId");
      expect(item).not.toHaveProperty("accountProof");
    }

    const privateCard = final.suspiciousCards[0]!;
    const browserJson = JSON.stringify(publicScanProgress(final));
    expect(browserJson).not.toContain(privateCard.envelope.providerNativeId);
    expect(browserJson).not.toContain(privateCard.envelope.messageId);
    expect(browserJson).not.toContain(privateCard.envelope.accountProof);
    expect(browserJson).not.toContain(privateCard.envelope.textPreview!);
    expect(browserJson).not.toContain('"links"');
    expect(browserJson).not.toContain('"attachments"');
  });
});
