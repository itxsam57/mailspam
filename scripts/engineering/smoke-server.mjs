import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { request as httpRequest } from "node:http";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = process.cwd();
const host = "127.0.0.1";
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-smoke-"));
let child;
let stdout = "";
let stderr = "";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function freePort() {
  return await new Promise((resolvePort, reject) => {
    const server = net.createServer();
    server.on("error", reject);
    server.listen(0, host, () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : null;
      server.close((error) => error ? reject(error) : resolvePort(port));
    });
  });
}

async function rawStatus(baseUrl, requestHeaders) {
  const url = new URL(baseUrl);
  return new Promise((resolveStatus, reject) => {
    const request = httpRequest({
      hostname: url.hostname,
      port: Number(url.port),
      path: "/",
      method: "GET",
      headers: requestHeaders,
    }, (response) => {
      response.resume();
      response.on("end", () => resolveStatus(response.statusCode ?? 0));
    });
    request.on("error", reject);
    request.end();
  });
}

async function waitForServer(baseUrl, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (child?.exitCode !== null) throw new Error(`Server exited before readiness with code ${child.exitCode}.\n${stderr}`);
    try {
      const response = await fetch(baseUrl, { signal: AbortSignal.timeout(2_000) });
      if (response.ok) return;
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 150));
  }
  throw new Error(`Server did not become ready: ${lastError?.message ?? "unknown error"}\n${stderr}`);
}

async function json(response, label) {
  const body = await response.json().catch(() => null);
  assert(response.ok, `${label} failed with HTTP ${response.status}: ${JSON.stringify(body)}`);
  return body;
}

try {
  const port = await freePort();
  assert(Number.isInteger(port), "Could not allocate an isolated smoke-test port.");
  const baseUrl = `http://${host}:${port}`;

  child = spawn(process.execPath, [resolve(root, "server/dist/index.js")], {
    cwd: root,
    env: {
      ...process.env,
      HOST: host,
      PORT: String(port),
      EMAIL_SHIELD_DATA_DIR: dataDir,
      EMAIL_SHIELD_COMMUNITY_SERVER: "0",
      EMAIL_SHIELD_COMMUNITY_URL: "",
      EMAIL_SHIELD_ENABLE_DEVELOPMENT_ENTITLEMENTS: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });

  await waitForServer(baseUrl);

  const home = await fetch(baseUrl, { signal: AbortSignal.timeout(5_000) });
  const homeHtml = await home.text();
  assert(home.status === 200, `Homepage returned HTTP ${home.status}.`);
  assert(homeHtml.includes("Email Shield"), "Homepage is missing the Email Shield application marker.");
  assert(homeHtml.includes('/local-security.js') && homeHtml.includes('/scan-monitor.js') && homeHtml.includes('/unsubscribe-monitor.js') && homeHtml.includes('/operations-dashboard.js'), "Dashboard response is missing local security, action or operations scripts.");
  assert(home.headers.get("content-security-policy")?.includes("frame-ancestors 'none'"), "Dashboard is missing its restrictive Content Security Policy.");
  const cookie = home.headers.get("set-cookie")?.split(";", 1)[0] ?? "";
  const csrf = homeHtml.match(/<meta name="email-shield-csrf" content="([^"]+)"/)?.[1] ?? "";
  assert(cookie.startsWith("email_shield_local_session="), "Dashboard did not issue an HttpOnly local session cookie.");
  assert(csrf.length >= 32, "Dashboard did not issue a browser CSRF token.");
  assert(!homeHtml.includes(cookie.split("=", 2)[1] ?? "missing-session"), "Dashboard HTML exposed the HttpOnly session secret.");

  const protectedHeaders = () => ({
    Cookie: cookie,
    Origin: baseUrl,
    Referer: `${baseUrl}/`,
    "X-Email-Shield-CSRF": csrf,
  });

  async function mutation(path, init = {}) {
    const nonceResponse = await fetch(`${baseUrl}/api/security/mutation-token`, {
      method: "POST",
      headers: protectedHeaders(),
      signal: AbortSignal.timeout(5_000),
    });
    const nonceBody = await json(nonceResponse, "Local mutation authorization");
    return fetch(`${baseUrl}${path}`, {
      ...init,
      method: init.method ?? "POST",
      headers: {
        ...protectedHeaders(),
        ...(init.headers ?? {}),
        "X-Email-Shield-Nonce": nonceBody.nonce,
      },
    });
  }

  const unauthenticated = await fetch(`${baseUrl}/api/accounts`, { signal: AbortSignal.timeout(5_000) });
  assert(unauthenticated.status === 401, `Unauthenticated account access returned HTTP ${unauthenticated.status}.`);

  const communityStatus = await json(
    await fetch(`${baseUrl}/api/community/v1/status`, { signal: AbortSignal.timeout(5_000) }),
    "Community client status",
  );
  assert(communityStatus.clientEnabled === true, "Community shield client is not enabled.");
  assert(communityStatus.aggregationServerEnabled === false, "Normal desktop smoke unexpectedly enabled central report ingestion.");
  assert(communityStatus.verifiedFeedAvailable === true, "Embedded signed community feed was not available.");
  assert(Number.isInteger(communityStatus.verifiedFeedEntries), "Community status did not report a feed-entry count.");
  assert((await fetch(`${baseUrl}/api/community/v1/feed`, { signal: AbortSignal.timeout(5_000) })).status === 404, "Normal client unexpectedly served the central signed feed endpoint.");
  assert((await fetch(`${baseUrl}/api/community/v1/public-key`, { signal: AbortSignal.timeout(5_000) })).status === 404, "Normal client unexpectedly served central public-key metadata.");

  const initialAccounts = await json(await fetch(`${baseUrl}/api/accounts`, {
    headers: protectedHeaders(),
  }), "Initial accounts request");
  assert(Array.isArray(initialAccounts) && initialAccounts.length === 0, "Smoke server did not start with an isolated empty session store.");

  const connected = await json(await mutation("/api/accounts/connect", {
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ provider: "gmail", mode: "fixture", label: "engineering-smoke" }),
    signal: AbortSignal.timeout(15_000),
  }), "Fixture account connection");
  assert(typeof connected.accountId === "string" && connected.provider === "gmail" && connected.mode === "fixture", "Fixture connection returned an unexpected contract.");
  assert(connected.community && Number.isInteger(connected.community.verifiedFeedEntries), "Fixture connection omitted community protection status.");

  const scanResponse = await fetch(`${baseUrl}/api/accounts/${encodeURIComponent(connected.accountId)}/scan/quick`, {
    headers: {
      Cookie: cookie,
      Origin: baseUrl,
      Referer: `${baseUrl}/`,
    },
    signal: AbortSignal.timeout(60_000),
  });
  const scanText = await scanResponse.text();
  assert(scanResponse.ok, `Quick-scan stream returned HTTP ${scanResponse.status}.`);
  assert(scanText.includes("event: scan-started"), "Quick-scan stream did not announce scan-started.");
  assert(scanText.includes("Refreshing verified community protection feed"), "Quick-scan stream did not announce community feed refresh.");
  assert(scanText.includes("event: scan-complete"), `Quick-scan stream did not complete.\n${scanText.slice(-1200)}`);

  const progressPayloads = scanText.split(/\r?\n/)
    .filter((line) => line.startsWith("data: "))
    .map((line) => {
      try { return JSON.parse(line.slice(6)); } catch { return null; }
    })
    .filter((value) => value && typeof value === "object" && value.counters);
  assert(progressPayloads.length > 0, "Quick-scan stream contained no progress payload.");
  const lastProgress = progressPayloads.at(-1);
  assert(lastProgress.counters.examined > 0, "Quick scan examined no fixture messages.");
  assert(Array.isArray(lastProgress.diagnosticSummaries) && lastProgress.diagnosticSummaries.length > 0, "Quick scan returned no diagnostic summaries.");
  assert(!scanText.includes('"listUnsubscribe":"http'), "Quick-scan stream exposed a raw unsubscribe destination.");
  assert(!scanText.includes('"campaignFingerprint"'), "Quick-scan stream exposed a private community campaign fingerprint.");
  assert(!scanText.includes('"reporterProof"'), "Quick-scan stream exposed a reporter proof.");

  for (const summary of lastProgress.diagnosticSummaries) {
    for (const forbidden of ["textPreview", "htmlSignals", "links", "attachments", "providerNativeId", "messageId", "actionContext", "communityReport"]) {
      assert(!(forbidden in summary), `Privacy-reduced diagnostic summary exposed ${forbidden}.`);
    }
    assert(typeof summary.subject === "string", "Diagnostic summary is missing its subject label.");
    assert(typeof summary.verdict === "string", "Diagnostic summary is missing its verdict.");
    assert(summary.reviewAction && typeof summary.reviewAction.token === "string", "Diagnostic summary is missing an opaque review token.");
  }

  const operationsResponse = await fetch(`${baseUrl}/api/operations/v1/snapshot`, {
    headers: protectedHeaders(),
    signal: AbortSignal.timeout(5_000),
  });
  const operations = await json(operationsResponse, "Privacy-safe operations snapshot");
  assert(operationsResponse.headers.get("cache-control") === "no-store", "Operations snapshot is cacheable.");
  assert(operations.schemaVersion === 1 && operations.privacy === "aggregate_only_no_mailbox_identity_or_content", "Operations snapshot omitted its strict privacy contract.");
  assert(operations.local?.providers?.gmail?.scans?.completed >= 1, "Operations snapshot did not record the compiled Gmail fixture scan.");
  assert(Array.isArray(operations.providerContracts) && operations.providerContracts.length === 5, "Operations snapshot omitted a provider contract.");
  const serializedOperations = JSON.stringify(operations);
  for (const forbidden of ["subject", "fromAddress", "messageId", "accountId", "providerNativeId", "exception", "token", "body"]) {
    assert(!serializedOperations.includes(`\"${forbidden}\"`), `Operations snapshot exposed forbidden field ${forbidden}.`);
  }

  const developerReport = await json(await fetch(`${baseUrl}/api/dev/test-suite`, {
    headers: protectedHeaders(),
    signal: AbortSignal.timeout(60_000),
  }), "Developer corpus suite");
  assert(developerReport.totalScans > 0, "Developer corpus suite ran zero scans.");
  assert(Array.isArray(developerReport.falsePositives) && developerReport.falsePositives.length === 0, `Developer corpus suite reported false positives: ${JSON.stringify(developerReport.falsePositives)}`);
  assert(Array.isArray(developerReport.falseNegatives) && developerReport.falseNegatives.length === 0, `Developer corpus suite reported false negatives: ${JSON.stringify(developerReport.falseNegatives)}`);
  assert(Array.isArray(developerReport.crossProviderParityFailures) && developerReport.crossProviderParityFailures.length === 0, `Developer corpus suite reported provider parity failures: ${JSON.stringify(developerReport.crossProviderParityFailures)}`);

  const removed = await mutation(`/api/accounts/${encodeURIComponent(connected.accountId)}`, {
    method: "DELETE",
    signal: AbortSignal.timeout(5_000),
  });
  assert(removed.status === 204, `Fixture account removal returned HTTP ${removed.status}.`);

  const replayNonce = await json(await fetch(`${baseUrl}/api/security/mutation-token`, {
    method: "POST",
    headers: protectedHeaders(),
  }), "Replay-test mutation authorization");
  const replayHeaders = { ...protectedHeaders(), "X-Email-Shield-Nonce": replayNonce.nonce };
  const firstReplayUse = await fetch(`${baseUrl}/api/accounts/connect`, {
    method: "POST",
    headers: { ...replayHeaders, "Content-Type": "application/json" },
    body: JSON.stringify({ provider: "gmail", mode: "fixture", label: "nonce-once" }),
  });
  assert(firstReplayUse.ok, "The first use of a mutation authorization failed unexpectedly.");
  const replayed = await fetch(`${baseUrl}/api/accounts/connect`, {
    method: "POST",
    headers: { ...replayHeaders, "Content-Type": "application/json" },
    body: JSON.stringify({ provider: "gmail", mode: "fixture", label: "nonce-replay" }),
  });
  assert(replayed.status === 409, `Replayed mutation authorization returned HTTP ${replayed.status}.`);

  const crossOriginNonce = await fetch(`${baseUrl}/api/security/mutation-token`, {
    method: "POST",
    headers: { ...protectedHeaders(), Origin: "http://127.0.0.1:65530" },
  });
  assert(crossOriginNonce.status === 403, `Cross-origin mutation authorization returned HTTP ${crossOriginNonce.status}.`);

  const rebindingStatus = await rawStatus(baseUrl, { Host: "attacker.example" });
  assert(rebindingStatus === 421, `DNS-rebinding Host request returned HTTP ${rebindingStatus}.`);

  const notFound = await fetch(`${baseUrl}/engineering-controlled-404`, { signal: AbortSignal.timeout(5_000) });
  assert(notFound.status === 404, `Unknown route returned HTTP ${notFound.status} instead of 404.`);

  console.log(`Compiled server/API smoke passed at ${baseUrl}.`);
  console.log(`Fixture messages examined: ${lastProgress.counters.examined}.`);
  console.log(`Verified community feed entries: ${communityStatus.verifiedFeedEntries}.`);
  console.log(`Developer corpus scans: ${developerReport.totalScans}.`);
  console.log("Local session, CSRF, one-time nonce, origin, and Host isolation checks passed.");
} catch (error) {
  console.error(`FAIL: ${error.message}`);
  if (stdout.trim()) console.error(`Server stdout:\n${stdout.trim()}`);
  if (stderr.trim()) console.error(`Server stderr:\n${stderr.trim()}`);
  process.exitCode = 1;
} finally {
  if (child && child.exitCode === null) {
    child.kill();
    await new Promise((resolveWait) => {
      const timer = setTimeout(() => {
        if (child.exitCode === null) child.kill("SIGKILL");
        resolveWait();
      }, 2_000);
      child.once("exit", () => {
        clearTimeout(timer);
        resolveWait();
      });
    });
  }
  rmSync(dataDir, { recursive: true, force: true });
}
