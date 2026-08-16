import { describe, expect, it } from "vitest";
import { ImapAdapter } from "../../server/src/adapters/imap/imapAdapter.js";
import type { FolderDescriptor } from "../../server/src/canonical/adapter.js";

describe("live IMAP provider body-fetch boundary", () => {
  it("never lets a caller turn one provider page into a 20-message body batch", async () => {
    const adapter = new ImapAdapter("icloud", {
      host: "imap.mail.me.com",
      port: 993,
      secure: true,
      user: "owner@example.test",
      appPassword: "test-only",
    });
    const folder: FolderDescriptor = {
      providerFolderName: "INBOX",
      normalized: "inbox",
      includedByDefault: true,
    };
    const metadataBatchSizes: number[] = [];
    const fakeClient = {
      mailbox: { uidValidity: "1" },
      getMailboxLock: async () => ({ release: () => undefined }),
      search: async () => Array.from({ length: 20 }, (_, index) => index + 1),
      fetchAll: async (uids: number[]) => {
        metadataBatchSizes.push(uids.length);
        return [];
      },
    };
    (adapter as unknown as { client: typeof fakeClient }).client = fakeClient;

    const page = await adapter.fetchPage(folder, null, 20, new AbortController().signal);

    expect(metadataBatchSizes).toEqual([2]);
    expect(page.envelopes).toHaveLength(2);
    expect(page.done).toBe(false);
    expect(page.nextCursor).not.toBeNull();
  });
});
