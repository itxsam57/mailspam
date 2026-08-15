import { beforeEach, describe, expect, it, vi } from "vitest";

const gmailMocks = vi.hoisted(() => ({
  getProfile: vi.fn(),
  listLabels: vi.fn(),
  listMessages: vi.fn(),
  getMessage: vi.fn(),
  batchModify: vi.fn(),
}));

vi.mock("@googleapis/gmail", () => ({
  gmail: vi.fn(() => ({
    users: {
      getProfile: gmailMocks.getProfile,
      labels: { list: gmailMocks.listLabels },
      messages: {
        list: gmailMocks.listMessages,
        get: gmailMocks.getMessage,
        batchModify: gmailMocks.batchModify,
      },
    },
  })),
}));

vi.mock("google-auth-library", () => ({
  OAuth2Client: class {
    setCredentials() {}
  },
}));

import { GmailAdapter } from "../../server/src/adapters/gmail/gmailAdapter.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { fullMailboxAudit } from "../../server/src/workflows/scanWorkflows.js";

function rawMessage(id: string): string {
  return Buffer.from([
    `From: Sender ${id} <${id}@example.test>`,
    "To: owner@example.test",
    `Subject: Full audit ${id}`,
    `Message-ID: <${id}@example.test>`,
    "Date: Sat, 15 Aug 2026 12:00:00 +0000",
    "Authentication-Results: mx.example.test; dkim=pass; spf=pass; dmarc=pass",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "",
    `Routine readable message ${id}. This content is intentionally harmless for the Gmail Full Audit contract.`,
  ].join("\r\n"), "utf8").toString("base64url");
}

function providerError(status: number) {
  return {
    response: {
      status,
      data: { error: { code: status, errors: [] } },
    },
  };
}

describe("Gmail Full Mailbox Audit workflow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    gmailMocks.getProfile.mockResolvedValue({ data: { emailAddress: "owner@example.test" } });
    gmailMocks.listLabels.mockResolvedValue({
      data: {
        labels: [
          { id: "INBOX" },
          { id: "SPAM" },
          { id: "SENT" },
          { id: "DRAFT" },
          { id: "TRASH" },
        ],
      },
    });

    gmailMocks.listMessages.mockImplementation(async (params: Record<string, unknown>) => {
      const labelIds = params.labelIds as string[] | undefined;
      const pageToken = params.pageToken as string | undefined;
      if (labelIds?.includes("INBOX")) {
        return pageToken === "inbox-next"
          ? { data: { messages: [{ id: "inbox-vanished" }] } }
          : { data: { messages: [{ id: "inbox-1" }, { id: "inbox-2" }], nextPageToken: "inbox-next" } };
      }
      if (labelIds?.includes("SPAM")) return { data: { messages: [] } };
      if (params.q === "in:archive") return { data: { messages: [{ id: "archive-1" }] } };
      throw new Error(`Unexpected Gmail list request: ${JSON.stringify(params)}`);
    });

    let archiveAttempts = 0;
    gmailMocks.getMessage.mockImplementation(async (params: { id: string }) => {
      if (params.id === "inbox-vanished") throw providerError(404);
      if (params.id === "archive-1") {
        archiveAttempts += 1;
        if (archiveAttempts === 1) throw providerError(429);
      }
      return { data: { raw: rawMessage(params.id) } };
    });
  });

  it("completes Inbox + empty Spam + Archive, retries transient quota errors, and skips vanished messages", async () => {
    const adapter = new GmailAdapter({
      clientId: "test-client-id",
      clientSecret: "test-client-secret",
      refreshToken: "test-refresh-token",
    });
    const signal = new AbortController().signal;
    const progress = [];

    for await (const update of fullMailboxAudit(
      adapter,
      {
        personalPolicy: new InMemoryPersonalPolicyStore(),
        threatFeed: { getVerifiedEntries: () => [] },
      },
      signal,
      { pageSize: 2 },
    )) {
      progress.push(update);
    }

    expect(progress.map((update) => update.folder)).toEqual([
      "INBOX",
      "INBOX",
      "SPAM",
      "in:archive",
    ]);
    expect(progress.at(-1)?.done).toBe(true);
    expect(progress.at(-1)?.counters.examined).toBe(3);
    expect(progress.flatMap((update) => update.diagnosticSummaries).map((summary) => summary.subject)).toEqual([
      "Full audit inbox-1",
      "Full audit inbox-2",
      "Full audit archive-1",
    ]);

    const spamRequest = gmailMocks.listMessages.mock.calls
      .map((call) => call[0] as Record<string, unknown>)
      .find((params) => Array.isArray(params.labelIds) && (params.labelIds as string[]).includes("SPAM"));
    expect(spamRequest).toMatchObject({
      labelIds: ["SPAM"],
      includeSpamTrash: true,
    });

    const archiveRequest = gmailMocks.listMessages.mock.calls
      .map((call) => call[0] as Record<string, unknown>)
      .find((params) => params.q === "in:archive");
    expect(archiveRequest).toMatchObject({ q: "in:archive" });
    expect("labelIds" in (archiveRequest ?? {})).toBe(false);

    expect(gmailMocks.getMessage.mock.calls.filter((call) => call[0].id === "archive-1")).toHaveLength(2);
    expect(gmailMocks.getMessage.mock.calls.filter((call) => call[0].id === "inbox-vanished")).toHaveLength(1);
  });
});
