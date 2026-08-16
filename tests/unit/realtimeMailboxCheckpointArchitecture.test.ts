import { readFileSync } from "node:fs";
import { basename, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const REPOSITORY_ROOT = basename(process.cwd()) === "server"
  ? resolve(process.cwd(), "..")
  : process.cwd();

function source(path: string): string {
  return readFileSync(resolve(REPOSITORY_ROOT, path), "utf8");
}

function methodBody(text: string, signature: string): string {
  const start = text.indexOf(signature);
  expect(start, `Missing ${signature}`).toBeGreaterThanOrEqual(0);
  const open = text.indexOf("{", start);
  expect(open, `Missing body for ${signature}`).toBeGreaterThanOrEqual(0);
  let depth = 0;
  for (let index = open; index < text.length; index += 1) {
    const char = text[index];
    if (char === "{") depth += 1;
    else if (char === "}") {
      depth -= 1;
      if (depth === 0) return text.slice(open + 1, index);
    }
  }
  throw new Error(`Unterminated method body for ${signature}`);
}

describe("realtime provider mailbox checkpoint architecture", () => {
  it("Gmail derives its heartbeat from profile/history metadata without listing or downloading messages", () => {
    const text = source("server/src/adapters/gmail/gmailAdapter.ts");
    const body = methodBody(text, "async mailboxCheckpoint");
    expect(text).toMatch(/historyId/);
    expect(body).not.toMatch(/messages\.(?:list|get)|fetchPage|raw/i);
  });

  it("Outlook heartbeat uses Graph metadata and never raw-message $value or the normal page pipeline", () => {
    const text = source("server/src/adapters/outlook/outlookAdapter.ts");
    const body = methodBody(text, "async mailboxCheckpoint");
    expect(body).toMatch(/receivedDateTime|totalItemCount|mailFolders/i);
    expect(body).not.toMatch(/\$value|fetchPage|rawBody|internetMessageHeaders/i);
  });

  it("IMAP heartbeat uses selected-mailbox metadata and never search/fetch/body-part acquisition", () => {
    const text = source("server/src/adapters/imap/imapAdapter.ts");
    const body = methodBody(text, "async mailboxCheckpoint");
    expect(body).toMatch(/getMailboxLock/);
    expect(body).toMatch(/uidValidity|uidNext|exists/);
    expect(body).not.toMatch(/\.search\s*\(|\.fetchAll\s*\(|\.fetchOne\s*\(|bodyParts|downloadAttachment/i);
  });

  it("the realtime probe composes through the shared adapter factory and never calls fetchPage", () => {
    const text = source("server/src/realtime/mailboxCheckpointProbe.ts");
    expect(text).toMatch(/createAdapter/);
    expect(text).toMatch(/mailboxCheckpoint/);
    expect(text).not.toMatch(/fetchPage|scanMessage|executeWithSummary/);
  });
});
