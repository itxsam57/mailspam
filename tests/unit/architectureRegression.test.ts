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

  it("never claims a Trash move without confirmation and a successful provider result", () => {
    const monitor = read("web/scan-monitor.js");
    expect(monitor).toContain("Move exactly this message to the provider Trash folder?");
    expect(monitor).toContain("providerNativeIds: [providerNativeId]");
    expect(monitor).toContain("result.requested !== 1 || result.moved !== 1 || failedReason");
    expect(monitor).toContain("Provider confirmed that exactly one message was moved to Trash.");
    expect(monitor).not.toContain(".then(() => { btn.textContent = 'Moved'");
  });

  it("scopes personal blocks to the selected account and verifies browser confirmation", () => {
    const server = read("server/src/api/server.ts");
    const sessions = read("server/src/api/sessionStore.ts");
    const monitor = read("web/scan-monitor.js");

    expect(sessions).toContain("personalPolicy: InMemoryPersonalPolicyStore");
    expect(sessions).not.toContain("readonly personalPolicy =");
    expect(server).toContain("personalPolicy: session.personalPolicy.snapshot()");
    expect(server).toContain("session.personalPolicy.blockSender(address)");
    expect(server).toContain("session.personalPolicy.blockDomain(domain)");
    expect(monitor).toContain("Block this ${scope} for the selected account?");
    expect(monitor).toContain("This does not move or delete mail.");
    expect(monitor).toContain("result.blocked !== true || result.scope !== scope || result.accountId !== id");
  });

  it("fetches bounded readable IMAP parts instead of raw messages or attachment bodies", () => {
    const imap = read("server/src/adapters/imap/imapAdapter.ts");
    expect(imap).not.toContain("source: true");
    expect(imap).not.toContain("MAX_MESSAGE_PREFIX_BYTES");
    expect(imap).toContain("bodyStructure: true");
    expect(imap).toContain("headers: true");
    expect(imap).toContain("client.download(uid, part");
    expect(imap).toContain("maxBytes: MAX_TEXT_PART_BYTES");
    expect(imap).not.toContain("downloadMany");
  });

  it("completes metadata fetches before issuing text-part downloads", () => {
    const imap = read("server/src/adapters/imap/imapAdapter.ts");
    expect(imap).toContain("client.fetchAll(selected");
    expect(imap).not.toContain("for await (const message of client.fetch");
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
