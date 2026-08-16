import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dirname, "../..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("transport architecture regressions", () => {
  it("has one explicit owner and one deterministic order for browser modules", () => {
    const composition = read("server/src/api/dashboardScripts.ts");
    const server = read("server/src/api/server.ts");
    const desktopServer = read("server/src/api/localDesktopServer.ts");
    const unsubscribe = read("web/unsubscribe-monitor.js");

    const scanIndex = composition.indexOf('"/scan-monitor.js"');
    const unsubscribeIndex = composition.indexOf('"/unsubscribe-monitor.js"');
    const reviewIndex = composition.indexOf('"/review-actions.js"');
    const safeAuditIndex = composition.indexOf('"/safe-audit.js"');
    expect(scanIndex).toBeGreaterThan(-1);
    expect(unsubscribeIndex).toBeGreaterThan(scanIndex);
    expect(reviewIndex).toBeGreaterThan(unsubscribeIndex);
    expect(safeAuditIndex).toBeGreaterThan(reviewIndex);
    expect(composition.match(/"\/review-actions\.js"/g)).toHaveLength(1);
    expect(composition.match(/"\/safe-audit\.js"/g)).toHaveLength(1);
    expect(server).toContain("dashboardScriptTags(false)");
    expect(desktopServer).toContain("dashboardScriptTags(true)");
    expect(unsubscribe).not.toContain("createElement('script')");
    expect(unsubscribe).not.toContain("/review-actions.js");
    expect(unsubscribe).not.toContain("/safe-audit.js");
  });

  it("makes every shared browser module installation idempotent", () => {
    for (const [path, moduleName] of [
      ["web/scan-monitor.js", "scan-monitor"],
      ["web/unsubscribe-monitor.js", "unsubscribe-monitor"],
      ["web/review-actions.js", "review-actions"],
      ["web/safe-audit.js", "safe-audit"],
    ] as const) {
      const source = read(path);
      expect(source).toContain("window.emailShieldInstalledModules ||= new Set()");
      expect(source).toContain(`installedModules.has('${moduleName}')`);
      expect(source).toContain(`installedModules.add('${moduleName}')`);
    }
  });

  it("refreshes operational health from the scan lifecycle instead of leaving a stale snapshot", () => {
    const operations = read("web/operations-dashboard.js");
    expect(operations).toContain("email-shield-scan-history-changed");
    expect(operations).toContain("dirty = true");
    expect(operations).toContain("loadWhenVisible()");
  });

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
    expect(packageJson).toContain('"dev": "tsx src/index.ts"');
    expect(packageJson).toContain('"start": "node dist/index.js"');
  });

  it("validates the protected browser session before opening a scan stream", () => {
    const server = read("server/src/api/server.ts");
    const monitor = read("web/scan-monitor.js");
    const sessionValidation = monitor.indexOf("await validateProtectedScanSession(requestedAccountId)");
    const eventSourceStart = monitor.indexOf("new EventSource");

    expect(server).toContain("scan-started");
    expect(server).toContain("scan-error");
    expect(monitor).toContain("scanMonitorStatus");
    expect(monitor).toContain("Could not open the scan stream");
    expect(monitor).toContain("The protected local session expired after the Email Shield process restarted");
    expect(sessionValidation).toBeGreaterThan(-1);
    expect(eventSourceStart).toBeGreaterThan(sessionValidation);
  });

  it("never claims a Trash move without confirmation and a successful provider result", () => {
    const monitor = read("web/scan-monitor.js");
    expect(monitor).toContain("Move exactly this message to the provider Trash folder?");
    expect(monitor).toContain("body: JSON.stringify({ token })");
    expect(monitor).not.toContain("providerNativeIds: [providerNativeId]");
    expect(monitor).toContain("result.requested !== 1 || result.moved !== 1 || failedReason");
    expect(monitor).toContain("Provider confirmed that exactly one message was moved to Trash.");
    expect(monitor).not.toContain(".then(() => { btn.textContent = 'Moved'");
  });

  it("scopes, encrypts, transactionally persists, and reverses personal blocks through Personal Policy Management", () => {
    const server = read("server/src/api/server.ts");
    const sessions = read("server/src/api/sessionStore.ts");
    const persistence = read("server/src/api/policyPersistence.ts");
    const dataDirectory = read("server/src/security/dataDirectory.ts");
    const monitor = read("web/scan-monitor.js");
    const review = read("web/review-actions.js");
    const policyUi = read("web/policy-management.js");
    const policyServer = read("server/src/api/policyManagement.ts");

    expect(sessions).toContain("policyStores = new Map");
    expect(sessions).toContain("policyRepository.load(accountKey)");
    expect(sessions).toContain("persistPersonalPolicy(session");
    expect(server).toContain("personalPolicy: session.personalPolicy.snapshot()");
    expect(server).toContain("mutateAndPersistPersonalPolicy");
    expect(server).toContain("persisted: sessionStore.personalPolicyPersistent()");
    expect(server).toContain("persistent: sessionStore.personalPolicyPersistent()");
    expect(server).not.toContain("persisted: true");
    expect(persistence).toContain('const ALGORITHM = "aes-256-gcm"');
    expect(persistence).toContain("defaultEmailShieldDataDirectory()");
    expect(dataDirectory).toContain('join(homedir(), ".email-shield")');
    expect(persistence).toContain("personal-policies.enc.json");
    expect(persistence).toContain("unsubscribedActions");
    expect(persistence).not.toContain("appPassword:");

    // Message-card Block is authorized only by the opaque scan capability. The
    // browser-rendered address/domain remains presentation, never mutation input.
    expect(monitor).toContain("body: JSON.stringify({ token })");
    expect(monitor).toContain("result.blocked !== true || result.scope !== scope || result.accountId !== id || result.token !== token");
    expect(monitor).toContain("attempt to move this current message to Trash");
    expect(review).not.toContain("dataset.action = 'unblock-sender'");
    expect(review).not.toContain("dataset.action = 'unblock-domain'");

    // Reversing a durable personal rule belongs to the encrypted Personal
    // Policy surface, which normalizes, transactionally replaces and persists
    // the selected account policy instead of reviving raw-address card routes.
    expect(policyUi).toContain("revoke.textContent = 'Revoke'");
    expect(policyUi).toContain("await mutate('/revoke'");
    expect(policyUi).toContain("await mutate('/bulk-revoke'");
    expect(policyUi).toContain("await mutate('/clear-category'");
    expect(policyServer).toContain('app.post("/api/accounts/:id/personal-policy/revoke"');
    expect(policyServer).toContain('app.post("/api/accounts/:id/personal-policy/bulk-revoke"');
    expect(policyServer).toContain('app.post("/api/accounts/:id/personal-policy/clear-category"');
    expect(policyServer).toContain("normalizePersonalPolicyValue(category, body.value)");
    expect(policyServer).toContain("revoked = removeOne(replacement, category, value)");
    expect(policyServer).toContain("sessionStore.mutateAndPersistPersonalPolicy(session, (policy) => policy.replace(replacement))");
  });

  it("uses opaque tokens for unsubscribe from both warning and Safe views", () => {
    const server = read("server/src/api/server.ts");
    const sessions = read("server/src/api/sessionStore.ts");
    const workflow = read("server/src/workflows/unsubscribe.ts");
    const scan = read("server/src/workflows/scanWorkflows.ts");
    const monitor = read("web/unsubscribe-monitor.js");
    const safeAudit = read("web/safe-audit.js");

    expect(server).toContain("registerPublicActions");
    expect(server).toContain("progress.diagnosticSummaries");
    expect(server).toContain("registerUnsubscribeAction");
    expect(server).toContain("resolveUnsubscribeAction");
    expect(server).toContain("delete summary.actionContext");
    expect(server).toContain("listUnsubscribe: null");
    expect(server).not.toContain("const { method, target } = req.body");
    expect(sessions).toContain("ACTION_TTL_MS");
    expect(sessions).toContain("unsubscribeActions: new Map()");
    expect(scan).toContain("unsubscribeCapability(result.envelope)");
    expect(workflow).toContain('const ONE_CLICK_BODY = "List-Unsubscribe=One-Click"');
    expect(workflow).toContain("resolvePinnedPublicAddress");
    expect(workflow).not.toContain('fetch(url, { method: "POST" })');
    expect(monitor).toContain("body: JSON.stringify({ token })");
    expect(monitor).toContain("Matching duplicate buttons were synchronized");
    expect(safeAudit).toContain('data-action="unsubscribe"');
  });

  it("registers Mark Safe and Trust sender for every canonical diagnostic result", () => {
    const server = read("server/src/api/server.ts");
    const sessions = read("server/src/api/sessionStore.ts");
    const scan = read("server/src/workflows/scanWorkflows.ts");
    const review = read("web/review-actions.js");
    const safeAudit = read("web/safe-audit.js");

    expect(scan).toContain("actionContext: ScanActionContext");
    expect(scan).toContain("messageExceptionKey(result.envelope)");
    expect(server).toContain("registerReviewAction");
    expect(server).toContain('/messages/mark-safe');
    expect(server).toContain('/messages/trust-sender');
    expect(sessions).toContain("reviewActions: new Map()");
    expect(review).toContain("Only this exact message will be approved");
    expect(review).toContain("Future messages from this exact sender address");
    expect(safeAudit).toContain('data-action="trust-sender"');
    expect(server).not.toContain('if (session.provider === "icloud")');
  });

  it("normalizes IMAP paths and special-use tokens before selecting INBOX", () => {
    const adapter = read("server/src/adapters/imap/imapAdapter.ts");
    const folders = read("server/src/adapters/imap/folderNames.ts");
    expect(adapter).toContain("normalizeImapFolder(folder)");
    expect(adapter).toContain("providerFolderPath(folder)");
    expect(folders).toContain('value === "inbox"');
    expect(folders).toContain('replace(/^\\\\+/, "")');
  });

  it("distinguishes bounded sufficient content from missing content", () => {
    const adapter = read("server/src/adapters/imap/imapAdapter.ts");
    const pipeline = read("server/src/engine/pipeline.ts");
    const verdict = read("server/src/engine/verdict.ts");
    expect(adapter).toContain('"bounded_sufficient"');
    expect(adapter).toContain("MIN_BOUNDED_VISIBLE_CHARS");
    expect(pipeline).toContain("boundedContentAllowsSafe");
    expect(pipeline).toContain("exactMessageApprovedByUser");
    expect(verdict).toContain("confirmedByRule");
    expect(verdict).toContain("exactMessageApprovedByUser");
  });

  it("uses stage-specific IMAP deadlines and force-closes stalled logout sockets", () => {
    const imap = read("server/src/adapters/imap/imapAdapter.ts");
    expect(imap).toContain("class ImapCommandTimeoutError");
    expect(imap).toContain("metadata fetch for ${selected.length} messages");
    expect(imap).toContain("UID search in ${folder.providerFolderName}");
    expect(imap).toContain("if (!logoutCompleted)");
    expect(imap).toContain("client.close()");
    expect(imap).not.toContain("IMAP command exceeded ${ms}ms deadline");
  });

  it("uses smaller live IMAP pages and retries only before visible progress", () => {
    const server = read("server/src/api/server.ts");
    const worker = read("server/src/workers/scanWorker.ts");
    expect(server).toContain('const pageSize = liveImap ? 10 : 20');
    expect(worker).toContain("runWithSingleRetry");
    expect(worker).toContain("firstAttemptHadProgress");
    expect(worker).toContain("if (firstAttemptHadProgress) throw error");
    expect(worker).toContain("Reconnecting and retrying the read-only scan once");
  });

  it("fetches bounded readable IMAP alternatives and bounded exact-hash parts without raw messages", () => {
    const imap = read("server/src/adapters/imap/imapAdapter.ts");
    const mime = read("server/src/adapters/imap/mimeParts.ts");
    const hashing = read("server/src/util/attachmentHash.ts");
    const normalizer = read("server/src/util/mimeNormalize.ts");
    expect(imap).not.toContain("source: true");
    expect(imap).not.toContain("MAX_MESSAGE_PREFIX_BYTES");
    expect(imap).toContain("bodyStructure: true");
    expect(imap).toContain("headers: true");
    expect(imap).toContain("bodyParts: requestedParts.map");
    expect(imap).toContain("MAX_COMPLETE_READABLE_PART_BYTES = 256 * 1024");
    expect(imap).toContain("readablePartFetchLimit(part)");
    expect(imap).toContain("part.sizeBytes! + 1");
    expect(imap).toContain(": MAX_ENCODED_TEXT_PART_BYTES");
    expect(imap).toContain("fetchBoundedAttachmentHashes");
    expect(imap).toContain("MAX_ENCODED_ATTACHMENT_HASH_PART_BYTES");
    expect(imap).toContain("MAX_ATTACHMENT_HASHES_PER_MESSAGE");
    expect(imap).toContain("qrByPart");
    expect(imap).toContain("hashesByAttachmentIndex");
    expect(imap).toContain("{ uid: true, binary: false }");
    expect(imap).toContain("buildSyntheticReadableMessage");
    expect(imap).toContain("boundedTextPartWasTruncated");
    expect(imap).not.toContain("expectedSize");
    expect(imap).not.toContain("downloadMany");
    expect(mime).toContain('isRoot && !node.childNodes?.length ? "TEXT"');
    expect(mime).toContain("decodeFetchedAttachmentPart");
    expect(mime).toContain("assertCompleteFetchedBinaryPart");
    expect(mime).toContain("rawPart.length < expectedBytes");
    expect(mime).toContain("hashableAttachments");
    expect(mime).toContain("plainBody");
    expect(mime).toContain("htmlBody");
    expect(hashing).toContain("MAX_ATTACHMENT_HASH_BYTES = 2 * 1024 * 1024");
    expect(hashing).toContain("MAX_ATTACHMENT_HASHES_PER_MESSAGE = 4");
    expect(normalizer).toContain("index < MAX_ATTACHMENT_HASHES_PER_MESSAGE");
    expect(normalizer).toContain("content.length <= MAX_ATTACHMENT_HASH_BYTES");
  });

  it("completes metadata fetches before issuing bounded text-part fetches", () => {
    const imap = read("server/src/adapters/imap/imapAdapter.ts");
    expect(imap).toContain("client.fetchAll(selected");
    expect(imap).toContain("fetchBoundedReadableBodies");
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