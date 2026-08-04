import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = join(process.cwd(), "..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("transport architecture regressions", () => {
  it("isolates scans in a killable worker", () => {
    const server = read("server/src/api/server.ts");
    expect(server).toContain("new Worker");
    expect(server).toContain("worker.terminate()");
  });
  it("does not fetch unrestricted complete IMAP sources", () => {
    const imap = read("server/src/adapters/imap/imapAdapter.ts");
    expect(imap).not.toContain("source: true");
    expect(imap).toContain("MAX_MESSAGE_PREFIX_BYTES");
  });
  it("does not invent UID ranges from uidNext", () => {
    const imap = read("server/src/adapters/imap/imapAdapter.ts");
    expect(imap).not.toContain("uidNext -");
    expect(imap).toContain("client.search({ all: true }");
  });
  it("keeps Microsoft continuation URLs opaque", () => {
    const outlook = read("server/src/adapters/outlook/outlookAdapter.ts");
    expect(outlook).not.toContain('searchParams.get("$skiptoken")');
    expect(outlook).toContain("nextCursor: nextLink ?? null");
  });
});
