import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = join(process.cwd(), "..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("transport architecture regressions", () => {
  it("isolates scans in a killable worker without cancelling on request completion", () => {
    const server = read("server/src/api/server.ts");
    expect(server).toContain("new Worker");
    expect(server).toContain("worker.terminate()");
    expect(server).toContain('res.on("close"');
    expect(server).not.toContain('req.on("close"');
  });
  it("launches the compiled JavaScript worker on every platform", () => {
    const server = read("server/src/api/server.ts");
    const packageJson = read("server/package.json");
    expect(server).toContain('new URL("../workers/scanWorker.js", import.meta.url)');
    expect(server).not.toContain("scanWorker.ts");
    expect(server).not.toContain('execArgv: ["--import", "tsx"]');
    expect(packageJson).toContain('"dev": "npm run build && node dist/index.js"');
  });
  it("surfaces scan startup and failures in the dashboard", () => {
    const server = read("server/src/api/server.ts");
    const monitor = read("web/scan-monitor.js");
    expect(server).toContain("scan-started");
    expect(server).toContain("scan-error");
    expect(monitor).toContain("scanMonitorStatus");
    expect(monitor).toContain("Could not open the scan stream");
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
