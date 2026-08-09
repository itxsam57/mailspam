import { describe, expect, it } from "vitest";
import { FixtureAdapter, type FixtureMessage } from "../../server/src/adapters/fixtures/fixtureAdapter.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import {
  fullMailboxAudit,
  quickScan,
  type ScanProgress,
} from "../../server/src/workflows/scanWorkflows.js";
import { publicScanProgress } from "../../server/src/api/scanStream.js";

function rawMessage(id: number, sender = "repeat@example.com"): string {
  return [
    `From: Example <${sender}>`,
    "To: local@example.test",
    `Subject: Resume test ${id}`,
    `Message-ID: <resume-${id}@example.test>`,
    "Date: Tue, 4 Aug 2026 12:00:00 +0000",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "",
    `Ordinary fixture message ${id} for resumable scan testing.`,
  ].join("\r\n");
}

function messages(): FixtureMessage[] {
  return [
    ...Array.from({ length: 4 }, (_, index) => ({
      id: `inbox-${index + 1}`,
      rawEml: rawMessage(index + 1),
      folder: "inbox" as const,
      providerFolderName: "INBOX",
    })),
    ...Array.from({ length: 2 }, (_, index) => ({
      id: `spam-${index + 1}`,
      rawEml: rawMessage(index + 5, `spam${index + 1}@example.net`),
      folder: "spam" as const,
      providerFolderName: "Spam",
    })),
  ];
}

function deps() {
  return {
    personalPolicy: new InMemoryPersonalPolicyStore(),
    threatFeed: { getVerifiedEntries: () => [] },
  };
}

describe("provider-neutral resumable scan workflows", () => {
  it("continues Quick Scan from the next provider page without resetting counters", async () => {
    let first: ScanProgress | null = null;
    for await (const progress of quickScan(
      new FixtureAdapter("gmail", messages()),
      deps(),
      new AbortController().signal,
      2,
      4,
    )) {
      first = progress;
      break;
    }

    expect(first).not.toBeNull();
    expect(first!.counters.examined).toBe(2);
    expect(first!.checkpoint.currentCursor).toBe("2");
    expect(first!.checkpoint.seenSenderHashes).toHaveLength(1);
    expect(first!.checkpoint.seenSenderHashes[0]).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify(first!.checkpoint)).not.toContain("repeat@example.com");

    const resumedProgress: ScanProgress[] = [];
    for await (const progress of quickScan(
      new FixtureAdapter("gmail", messages()),
      deps(),
      new AbortController().signal,
      2,
      4,
      {
        ...first!.checkpoint,
        counters: first!.counters,
      },
    )) resumedProgress.push(progress);

    expect(resumedProgress).toHaveLength(1);
    expect(resumedProgress[0]!.counters.examined).toBe(4);
    expect(resumedProgress[0]!.done).toBe(true);
    expect(resumedProgress[0]!.checkpoint.currentCursor).toBeNull();
  });

  it("resumes Full Mailbox Audit without re-reading completed pages and carries completed-folder state forward", async () => {
    let first: (ScanProgress & { folder: string }) | null = null;
    for await (const progress of fullMailboxAudit(
      new FixtureAdapter("gmail", messages()),
      deps(),
      new AbortController().signal,
      { pageSize: 2 },
    )) {
      first = progress;
      break;
    }

    expect(first).not.toBeNull();
    expect(first!.folder).toBe("INBOX");
    expect(first!.counters.examined).toBe(2);
    expect(first!.checkpoint.folderCursors.INBOX).toBe("2");
    expect(first!.checkpoint.seenMessageHashes).toHaveLength(2);

    const resumed: Array<ScanProgress & { folder: string }> = [];
    for await (const progress of fullMailboxAudit(
      new FixtureAdapter("gmail", messages()),
      deps(),
      new AbortController().signal,
      {
        pageSize: 2,
        resume: {
          ...first!.checkpoint,
          counters: first!.counters,
        },
      },
    )) resumed.push(progress);

    expect(resumed.length).toBeGreaterThanOrEqual(2);
    expect(resumed[0]!.counters.examined).toBe(4);
    expect(resumed.at(-1)!.counters.examined).toBe(6);
    expect(resumed.at(-1)!.done).toBe(true);
    expect(resumed.at(-1)!.checkpoint.completedFolders).toEqual(expect.arrayContaining(["INBOX", "Spam"]));
    expect(resumed.at(-1)!.checkpoint.folderCursors).toEqual({});
  });

  it("removes provider cursors and resumability hashes from browser-facing scan progress", async () => {
    let first: ScanProgress | null = null;
    for await (const progress of quickScan(
      new FixtureAdapter("gmail", messages()),
      deps(),
      new AbortController().signal,
      2,
      4,
    )) {
      first = progress;
      break;
    }
    const publicValue = publicScanProgress(first!);
    expect(publicValue).not.toHaveProperty("cursor");
    expect(publicValue).not.toHaveProperty("checkpoint");
    expect(JSON.stringify(publicValue)).not.toContain('"currentCursor"');
    expect(JSON.stringify(publicValue)).not.toContain('"seenSenderHashes"');
    expect(JSON.stringify(publicValue)).not.toContain('"seenMessageHashes"');
  });
});
