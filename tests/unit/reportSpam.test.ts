import { describe, expect, it } from "vitest";
import type {
  EmailAdapter,
  FetchPage,
  FolderDescriptor,
  SpamReportResult,
} from "../../server/src/canonical/adapter.js";
import type { Provider } from "../../server/src/canonical/envelope.js";
import { FixtureAdapter, type FixtureMessage } from "../../server/src/adapters/fixtures/fixtureAdapter.js";
import { reportMessagesAsSpam } from "../../server/src/workflows/reportSpam.js";

const signal = () => new AbortController().signal;

function raw(subject: string): string {
  return [
    "From: Sender <sender@example.test>",
    `Subject: ${subject}`,
    `Message-ID: <${subject.toLowerCase().replace(/\W+/g, "-")}@example.test>`,
    "Date: Thu, 1 Jan 2026 00:00:00 +0000",
    "Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Readable fixture message content.",
  ].join("\r\n");
}

function mockAdapter(reportResult: SpamReportResult | Error): EmailAdapter {
  return {
    provider: "gmail",
    async connect() {},
    async listFolders(): Promise<FolderDescriptor[]> { return []; },
    async fetchPage(): Promise<FetchPage> { return { envelopes: [], nextCursor: null, done: true }; },
    async moveToTrash() {},
    async reportSpam(ids) {
      if (reportResult instanceof Error) throw reportResult;
      return reportResult;
    },
    async disconnect() {},
  };
}

describe("reportMessagesAsSpam", () => {
  it("accepts only an exact provider confirmation", async () => {
    const result = await reportMessagesAsSpam(
      mockAdapter({ requested: 1, reported: 1, mode: "provider_spam_label" }),
      ["message-1"],
      signal(),
    );
    expect(result).toEqual({
      requested: 1,
      reported: 1,
      mode: "provider_spam_label",
      failed: [],
    });
  });

  it("does not claim success when the provider confirms fewer messages", async () => {
    const result = await reportMessagesAsSpam(
      mockAdapter({ requested: 1, reported: 0, mode: "junk_folder_move" }),
      ["message-1"],
      signal(),
    );
    expect(result.reported).toBe(0);
    expect(result.mode).toBeNull();
    expect(result.failed).toEqual([
      expect.objectContaining({ messageId: "message-1", reason: expect.stringContaining("Provider reported 0 of 1") }),
    ]);
  });

  it("surfaces provider errors for every exact requested identifier", async () => {
    const result = await reportMessagesAsSpam(
      mockAdapter(new Error("Junk folder unavailable")),
      ["message-1", "message-2"],
      signal(),
    );
    expect(result.reported).toBe(0);
    expect(result.failed).toEqual([
      { messageId: "message-1", reason: "Junk folder unavailable" },
      { messageId: "message-2", reason: "Junk folder unavailable" },
    ]);
  });
});

describe("fixture provider Spam/Junk behavior", () => {
  for (const provider of ["gmail", "icloud", "outlook", "yahoo", "imap"] as Provider[]) {
    it(`${provider} moves only the selected fixture message from Inbox to Spam`, async () => {
      const messages: FixtureMessage[] = [
        { id: "selected", rawEml: raw("Selected"), folder: "inbox", providerFolderName: "INBOX" },
        { id: "unrelated", rawEml: raw("Unrelated"), folder: "inbox", providerFolderName: "INBOX" },
        { id: "existing-spam", rawEml: raw("Existing spam"), folder: "spam", providerFolderName: "Spam" },
      ];
      const adapter = new FixtureAdapter(provider, messages);
      const abortSignal = signal();
      await adapter.connect(abortSignal);

      const result = await reportMessagesAsSpam(adapter, ["selected"], abortSignal);
      expect(result).toMatchObject({ requested: 1, reported: 1, mode: "fixture_junk_move", failed: [] });

      const folders = await adapter.listFolders(abortSignal);
      const inbox = folders.find((folder) => folder.normalized === "inbox")!;
      const spam = folders.find((folder) => folder.normalized === "spam")!;
      const inboxPage = await adapter.fetchPage(inbox, null, 20, abortSignal);
      const spamPage = await adapter.fetchPage(spam, null, 20, abortSignal);

      expect(inboxPage.envelopes.map((item) => item.providerNativeId)).toEqual(["unrelated"]);
      expect(spamPage.envelopes.map((item) => item.providerNativeId)).toEqual(expect.arrayContaining(["selected", "existing-spam"]));
      expect(spamPage.envelopes.map((item) => item.providerNativeId)).toHaveLength(2);
      await adapter.disconnect();
    });
  }

  it("does not invoke spam reporting during an ordinary scan", async () => {
    let reportCalls = 0;
    const adapter: EmailAdapter = {
      provider: "imap",
      async connect() {},
      async listFolders() { return [{ providerFolderName: "INBOX", normalized: "inbox", includedByDefault: true }]; },
      async fetchPage() { return { envelopes: [], nextCursor: null, done: true }; },
      async moveToTrash() {},
      async reportSpam() {
        reportCalls++;
        return { requested: 0, reported: 0, mode: "junk_folder_move" };
      },
      async disconnect() {},
    };
    await adapter.connect(signal());
    await adapter.fetchPage((await adapter.listFolders(signal()))[0]!, null, 10, signal());
    await adapter.disconnect();
    expect(reportCalls).toBe(0);
  });
});
