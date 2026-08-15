import { describe, expect, it } from "vitest";
import {
  gmailMessageListParameters,
  resolveGmailFolderDescriptors,
} from "../../server/src/adapters/gmail/gmailAdapter.js";

describe("Gmail folder listing contract", () => {
  it("keeps default Full Audit on Inbox, Spam and Archive while excluding Sent, Drafts and Trash", () => {
    const folders = resolveGmailFolderDescriptors([
      "INBOX",
      "SPAM",
      "SENT",
      "DRAFT",
      "TRASH",
      "IMPORTANT",
      "CATEGORY_UPDATES",
    ]);

    expect(folders.map((folder) => [folder.providerFolderName, folder.normalized, folder.includedByDefault])).toEqual([
      ["INBOX", "inbox", true],
      ["SPAM", "spam", true],
      ["SENT", "sent", false],
      ["DRAFT", "drafts", false],
      ["TRASH", "trash", false],
      ["in:archive", "archive", true],
    ]);

    expect(folders.filter((folder) => folder.includedByDefault).map((folder) => folder.normalized)).toEqual([
      "inbox",
      "spam",
      "archive",
    ]);
  });

  it("requests Spam with includeSpamTrash instead of silently receiving a standard-mail-only result", () => {
    const spam = resolveGmailFolderDescriptors(["SPAM"]).find((folder) => folder.normalized === "spam")!;
    expect(gmailMessageListParameters(spam, "spam-cursor", 75)).toEqual({
      userId: "me",
      maxResults: 75,
      pageToken: "spam-cursor",
      labelIds: ["SPAM"],
      includeSpamTrash: true,
    });
  });

  it("uses Gmail's archive search grammar with no invented ALL_MAIL label ID", () => {
    const archive = resolveGmailFolderDescriptors([]).find((folder) => folder.normalized === "archive")!;
    expect(gmailMessageListParameters(archive, "archive-cursor", 75)).toEqual({
      userId: "me",
      maxResults: 75,
      pageToken: "archive-cursor",
      q: "in:archive",
    });
  });

  it("preserves Quick Scan's Inbox list request and pagination semantics", () => {
    const inbox = resolveGmailFolderDescriptors(["INBOX"]).find((folder) => folder.normalized === "inbox")!;
    expect(gmailMessageListParameters(inbox, null, 20)).toEqual({
      userId: "me",
      maxResults: 20,
      pageToken: undefined,
      labelIds: ["INBOX"],
    });
    expect(gmailMessageListParameters(inbox, "next-inbox-page", 75)).toEqual({
      userId: "me",
      maxResults: 75,
      pageToken: "next-inbox-page",
      labelIds: ["INBOX"],
    });
  });

  it("also requests explicitly selected Trash with includeSpamTrash", () => {
    const trash = resolveGmailFolderDescriptors(["TRASH"]).find((folder) => folder.normalized === "trash")!;
    expect(gmailMessageListParameters(trash, null, 75)).toMatchObject({
      labelIds: ["TRASH"],
      includeSpamTrash: true,
    });
  });
});
