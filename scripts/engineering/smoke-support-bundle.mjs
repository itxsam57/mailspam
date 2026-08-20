import { spawn, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
} from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { waitForDevToolsPort } from "./chromium-devtools-port.mjs";

const root = process.cwd();
const host = "127.0.0.1";
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-support-data-"));
const browserProfile = mkdtempSync(join(tmpdir(), "email-shield-support-profile-"));
const downloadDir = mkdtempSync(join(tmpdir(), "email-shield-support-download-"));
let server;
let browser;
let socket;
let serverStderr = "";
let browserStderr = "";

const FORBIDDEN_KEYS = new Set([
  "accesstoken",
  "refreshtoken",
  "apppassword",
  "subject",
  "body",
  "bodytext",
  "rawbody",
  "senderaddress",
  "mailboxaddress",
  "recipientaddress",
  "mailboxaccountkey",
  "providernativeid",
  "messageid",
  "rawurl",
  "deviceprivatekey",
  "publickeyspki",
  "recoverycode",
  "recoverycodehash",
  "traceid",
  "requestbody",
  "formvalues",
  "rawerror",
  "stack",
]);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const sleep = (ms) => new Promise((resolveWait) => setTimeout(resolveWait, ms));

function childProcessExited(processRef) {
  return processRef.exitCode !== null || processRef.signalCode !== null;
}

async function stopChildProcess(processRef, label, timeoutMs = 5_000) {
  if (!processRef || childProcessExited(processRef)) return;
  const exited = new Promise((resolveExit) => processRef.once("exit", resolveExit));
  try { processRef.kill(); } catch {}
  await Promise.race([exited, sleep(timeoutMs)]);
  if (!childProcessExited(processRef)) {
    try { processRef.kill("SIGKILL"); } catch {}
    await Promise.race([exited, sleep(1_000)]);
  }
  if (!childProcessExited(processRef)) {
    throw new Error(`${label} did not exit during Support Bundle teardown.`);
  }
}

async function freePort() {
  return await new Promise((resolvePort, reject) => {
    const listener = net.createServer();
    listener.on("error", reject);
    listener.listen(0, host, () => {
      const address = listener.address();
      listener.close((error) => error ? reject(error) : resolvePort(address.port));
    });
  });
}

async function waitForHttp(url, processRef, stderr, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (processRef?.exitCode !== null) throw new Error(`Process exited before ${url} became ready.\n${stderr()}`);
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(2_000) });
      if (response.ok) return;
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) { lastError = error; }
    await sleep(100);
  }
  throw new Error(`Timed out waiting for ${url}: ${lastError?.message ?? "unknown error"}`);
}

function findOnPath(command) {
  const result = spawnSync(process.platform === "win32" ? "where" : "which", [command], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  return result.status === 0
    ? result.stdout.split(/\r?\n/).map((line) => line.trim()).find(Boolean) ?? null
    : null;
}

function findBrowser() {
  const configured = process.env.EMAIL_SHIELD_TEST_BROWSER?.trim();
  if (configured) {
    assert(existsSync(configured), `EMAIL_SHIELD_TEST_BROWSER does not exist: ${configured}`);
    return configured;
  }
  const candidates = [];
  if (process.platform === "win32") {
    for (const base of [process.env.PROGRAMFILES, process.env["PROGRAMFILES(X86)"], process.env.LOCALAPPDATA]) {
      if (!base) continue;
      candidates.push(join(base, "Google", "Chrome", "Application", "chrome.exe"));
      candidates.push(join(base, "Microsoft", "Edge", "Application", "msedge.exe"));
    }
  } else if (process.platform === "darwin") {
    candidates.push(
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
      "/Applications/Chromium.app/Contents/MacOS/Chromium",
    );
  } else {
    candidates.push(
      "/usr/bin/google-chrome",
      "/usr/bin/google-chrome-stable",
      "/usr/bin/chromium",
      "/usr/bin/chromium-browser",
      "/usr/bin/microsoft-edge",
    );
  }
  const direct = candidates.find((candidate) => existsSync(candidate));
  if (direct) return direct;
  const commands = process.platform === "win32"
    ? ["chrome.exe", "msedge.exe"]
    : ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge"];
  for (const command of commands) {
    const found = findOnPath(command);
    if (found) return found;
  }
  throw new Error("No Chrome, Chromium, or Edge executable was found for the Support Bundle gate.");
}

async function connectWebSocket(url, timeoutMs = 10_000) {
  return await new Promise((resolveSocket, reject) => {
    const candidate = new WebSocket(url);
    const timer = setTimeout(() => reject(new Error(`Timed out connecting to DevTools: ${url}`)), timeoutMs);
    candidate.addEventListener("open", () => { clearTimeout(timer); resolveSocket(candidate); }, { once: true });
    candidate.addEventListener("error", () => { clearTimeout(timer); reject(new Error(`Could not connect to DevTools: ${url}`)); }, { once: true });
  });
}

function createClient(ws) {
  let nextId = 1;
  const pending = new Map();
  const listeners = new Map();
  ws.addEventListener("message", (event) => {
    let message;
    try { message = JSON.parse(String(event.data)); } catch { return; }
    if (typeof message.id === "number") {
      const waiter = pending.get(message.id);
      if (!waiter) return;
      pending.delete(message.id);
      if (message.error) waiter.reject(new Error(`${waiter.method}: ${message.error.message ?? "DevTools error"}`));
      else waiter.resolve(message.result ?? {});
      return;
    }
    for (const listener of listeners.get(message.method) ?? []) listener(message.params ?? {});
  });
  return {
    on(method, listener) {
      const bucket = listeners.get(method) ?? new Set();
      bucket.add(listener);
      listeners.set(method, bucket);
    },
    send(method, params = {}, timeoutMs = 10_000) {
      const id = nextId++;
      return new Promise((resolveResult, reject) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`DevTools command timed out: ${method}`));
        }, timeoutMs);
        pending.set(id, {
          method,
          resolve: (value) => { clearTimeout(timer); resolveResult(value); },
          reject: (error) => { clearTimeout(timer); reject(error); },
        });
        ws.send(JSON.stringify({ id, method, params }));
      });
    },
  };
}

async function evaluate(client, expression, timeoutMs = 10_000) {
  const result = await client.send("Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise: true,
  }, timeoutMs);
  if (result.exceptionDetails) {
    throw new Error(result.exceptionDetails.exception?.description ?? result.exceptionDetails.text ?? "Browser evaluation failed");
  }
  return result.result?.value;
}

function objectKeys(value, keys = new Set()) {
  if (Array.isArray(value)) {
    for (const item of value) objectKeys(item, keys);
    return keys;
  }
  if (!value || typeof value !== "object") return keys;
  for (const [key, child] of Object.entries(value)) {
    keys.add(key.toLowerCase());
    objectKeys(child, keys);
  }
  return keys;
}

async function waitForDownloadedJson(timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const file = readdirSync(downloadDir)
      .find((name) => name.endsWith(".json") && !name.endsWith(".crdownload"));
    if (file) return join(downloadDir, file);
    await sleep(100);
  }
  throw new Error("Support Bundle button did not produce a JSON download.");
}

try {
  const port = await freePort();
  const baseUrl = `http://${host}:${port}`;
  server = spawn(process.execPath, [resolve(root, "server/dist/index.js")], {
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
    stdio: ["ignore", "ignore", "pipe"],
  });
  server.stderr.setEncoding("utf8");
  server.stderr.on("data", (chunk) => { serverStderr += chunk; });
  await waitForHttp(baseUrl, server, () => serverStderr);

  const executable = findBrowser();
  browser = spawn(executable, [
    "--headless=new",
    "--remote-debugging-port=0",
    "--remote-debugging-address=127.0.0.1",
    `--user-data-dir=${browserProfile}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-sync",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "about:blank",
  ], { stdio: ["ignore", "ignore", "pipe"] });
  browser.stderr.setEncoding("utf8");
  browser.stderr.on("data", (chunk) => { browserStderr += chunk; });

  const debugPort = await waitForDevToolsPort(browserProfile, browser, () => browserStderr);
  await waitForHttp(`http://${host}:${debugPort}/json/version`, browser, () => browserStderr, 15_000);
  const targets = await (await fetch(`http://${host}:${debugPort}/json/list`, { signal: AbortSignal.timeout(5_000) })).json();
  const target = Array.isArray(targets) ? targets.find((item) => item.type === "page" && item.webSocketDebuggerUrl) : null;
  assert(target?.webSocketDebuggerUrl, "Browser DevTools exposed no page target.");

  socket = await connectWebSocket(target.webSocketDebuggerUrl);
  const client = createClient(socket);
  const runtimeErrors = [];
  client.on("Runtime.exceptionThrown", ({ exceptionDetails }) => runtimeErrors.push(
    exceptionDetails?.exception?.description ?? exceptionDetails?.text ?? "browser exception",
  ));
  await Promise.all([client.send("Page.enable"), client.send("Runtime.enable")]);
  await client.send("Page.setDownloadBehavior", { behavior: "allow", downloadPath: downloadDir });
  const navigation = await client.send("Page.navigate", { url: `${baseUrl}/?developer=1` }, 15_000);
  assert(!navigation.errorText, `Browser navigation failed: ${navigation.errorText}`);

  const readyDeadline = Date.now() + 15_000;
  let ready = false;
  while (Date.now() < readyDeadline) {
    ready = await evaluate(client, `Boolean(
      document.readyState === 'complete' &&
      window.emailShieldSecureFetchInstalled === true &&
      window.emailShieldInstalledModules?.has('consumer-product') &&
      window.emailShieldInstalledModules?.has('health-cleanup-controller') &&
      typeof window.emailShieldSelectAccount === 'function' &&
      typeof window.emailShieldNavigate === 'function' &&
      document.getElementById('consumerSupportBundle')
    )`).catch(() => false);
    if (ready) break;
    await sleep(100);
  }
  assert(ready, "Support Bundle browser gate could not reach the initialized consumer dashboard.");

  const accountId = await evaluate(client, `(async () => {
    const response = await fetch('/api/accounts/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'gmail', mode: 'fixture', label: 'support-bundle-fixture' }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || typeof body.accountId !== 'string') throw new Error(body.error || 'Fixture connection failed.');
    await refreshAccounts();
    window.emailShieldSelectAccount(body.accountId, { remember: false });
    return body.accountId;
  })()`, 20_000);
  assert(typeof accountId === "string" && accountId, "Support Bundle fixture account was not created.");

  const scanResult = await evaluate(client, `(async () => {
    const response = await fetch('/api/accounts/${accountId}/scan/quick', { cache: 'no-store' });
    const text = await response.text();
    return { ok: response.ok, text };
  })()`, 60_000);
  assert(scanResult?.ok === true && /scan-complete/.test(scanResult.text || ""), "Quick Scan did not complete before Support Bundle export.");

  await evaluate(client, `(() => {
    window.emailShieldNavigate('protection', { focus: false });
    document.getElementById('consumerRunHealth').click();
    return true;
  })()`);

  let cleanupBefore = null;
  const healthDeadline = Date.now() + 35_000;
  while (Date.now() < healthDeadline) {
    cleanupBefore = await evaluate(client, `(() => {
      const rows = [...document.querySelectorAll('#consumerSubscriptions .consumer-list-item')];
      const row = rows.find((candidate) => candidate.querySelector('button[data-health-cleanup-key]')) || null;
      const button = row?.querySelector('button[data-health-cleanup-key]') || null;
      const eligibility = row?.querySelector('.health-cleanup-eligibility')?.textContent || '';
      const match = eligibility.match(/(\\d+) message\\(s\\) older than 30 days/);
      return {
        label: row?.querySelector('strong')?.textContent?.trim() || '',
        key: button?.dataset.healthCleanupKey || '',
        oldCount: Number(match?.[1] || 0),
      };
    })()`);
    if (cleanupBefore?.key && cleanupBefore.oldCount > 0) break;
    await sleep(100);
  }
  assert(cleanupBefore?.key && cleanupBefore.oldCount > 0, `Health exposed no old-mail cleanup target. State: ${JSON.stringify(cleanupBefore)}`);

  const cleanupLabel = JSON.stringify(cleanupBefore.label);
  await evaluate(client, `(() => {
    window.confirm = () => true;
    window.prompt = () => 'MOVE TO TRASH';
    const row = [...document.querySelectorAll('#consumerSubscriptions .consumer-list-item')]
      .find((candidate) => candidate.querySelector('strong')?.textContent?.trim() === ${cleanupLabel});
    const button = row?.querySelector('button[data-health-cleanup-key]');
    if (!button) throw new Error('Authoritative cleanup control disappeared before click.');
    button.click();
    return true;
  })()`);

  let cleanupActivity = null;
  const cleanupDeadline = Date.now() + 40_000;
  while (Date.now() < cleanupDeadline) {
    cleanupActivity = await evaluate(client, `(async () => {
      const response = await fetch('/api/consumer/v1/accounts/${accountId}/activity', { cache: 'no-store' });
      const body = await response.json().catch(() => ({}));
      const item = Array.isArray(body.activity)
        ? body.activity.find((entry) => entry?.kind === 'cleanup') || null
        : null;
      return { ok: response.ok, title: item?.title || '', reasonCodes: item?.reasonCodes || [] };
    })()`);
    if (cleanupActivity?.ok && cleanupActivity.title) break;
    await sleep(100);
  }
  assert(cleanupActivity?.title === "Mailbox cleanup completed", `Health cleanup did not produce a completed mutation Activity record: ${JSON.stringify(cleanupActivity)}`);
  assert(cleanupActivity.reasonCodes?.includes("BULK_CLEANUP_TO_TRASH"), `Health cleanup did not record the mutation reason code: ${JSON.stringify(cleanupActivity)}`);

  const background = await evaluate(client, `(async () => {
    const response = await fetch('/api/accounts/${accountId}/background-protection', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: true, intervalMinutes: 30 }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || 'Background protection configuration failed.');
    return body;
  })()`);
  assert(background?.enabled === true && background?.intervalMinutes === 30, `Background schedule did not persist the 30-minute contract: ${JSON.stringify(background)}`);

  await evaluate(client, `(() => {
    window.emailShieldNavigate('settings', { focus: false });
    const button = document.getElementById('consumerSupportBundle');
    if (!button) throw new Error('Support Bundle export button is missing.');
    button.click();
    return true;
  })()`);

  const downloaded = await waitForDownloadedJson();
  const bundle = JSON.parse(readFileSync(downloaded, "utf8"));
  assert(bundle.schemaVersion === 1, "Support Bundle schema version changed unexpectedly.");
  assert(bundle.privacy === "no_credentials_tokens_mail_content_subject_sender_url_family_private_data_or_device_keys", "Support Bundle privacy contract changed unexpectedly.");
  assert(bundle.activityScope?.scope === "persisted_local_activity", `Activity scope is not explicit: ${JSON.stringify(bundle.activityScope)}`);
  assert(bundle.operationalScope?.scope === "current_process", `Operational scope is not explicit: ${JSON.stringify(bundle.operationalScope)}`);
  assert(bundle.operationalScope?.workerAdapterAggregatesMergedIntoMainProcess === true, "Worker adapter aggregation is not declared in the exported Support Bundle.");
  assert(bundle.scanHistory?.scope === "persisted_local_scan_history", `Scan-history scope is missing: ${JSON.stringify(bundle.scanHistory)}`);
  assert(Number(bundle.scanHistory?.retainedRecords || 0) >= 1, `Completed Quick Scan disappeared from persisted Support Bundle diagnostics: ${JSON.stringify(bundle.scanHistory)}`);
  assert(Number(bundle.scanHistory?.counters?.examined || 0) > 0, `Persisted scan counters did not reflect the real Quick Scan: ${JSON.stringify(bundle.scanHistory)}`);
  assert(Number(bundle.cleanup?.completedWithMutation || 0) >= 1, `Real Health cleanup mutation disappeared from Support Bundle diagnostics: ${JSON.stringify(bundle.cleanup)}`);
  assert(Number(bundle.operational?.providers?.gmail?.operations?.move_to_trash?.succeeded || 0) >= 1, `Health Worker move-to-trash operation was not merged into main-process diagnostics: ${JSON.stringify(bundle.operational?.providers?.gmail?.operations?.move_to_trash)}`);
  assert(bundle.backgroundProtection?.available === true, "Support Bundle could not see the runtime background coordinator.");
  assert(Number(bundle.backgroundProtection?.coordinator?.schedulerLoopCount || 0) >= 1, `Scheduler bootstrap/loop evidence is absent: ${JSON.stringify(bundle.backgroundProtection?.coordinator)}`);
  const gmailSchedule = Array.isArray(bundle.backgroundProtection?.statuses)
    ? bundle.backgroundProtection.statuses.find((item) => item?.provider === "gmail")
    : null;
  assert(gmailSchedule?.enabled === true && Number(gmailSchedule?.nextRunAt || 0) > 0, `Configured Gmail background schedule is absent from Support Bundle: ${JSON.stringify(gmailSchedule)}`);
  assert(bundle.workflowDiagnosis && typeof bundle.workflowDiagnosis === "object", "Sanitized EMA-5 workflow diagnosis section is absent.");

  const keys = objectKeys(bundle);
  const forbidden = [...keys].filter((key) => FORBIDDEN_KEYS.has(key));
  assert(forbidden.length === 0, `Support Bundle exported forbidden diagnostic keys: ${forbidden.join(", ")}`);
  const serialized = JSON.stringify(bundle);
  assert(!serialized.includes(accountId), "Support Bundle leaked the connected session/account identifier.");
  assert(runtimeErrors.length === 0, `Support Bundle flow produced uncaught browser errors: ${JSON.stringify(runtimeErrors)}`);

  console.log(`Executable Support Bundle smoke passed with ${executable}.`);
  console.log(`Export reconciled ${bundle.scanHistory.retainedRecords} persisted scan record(s), ${bundle.cleanup.completedWithMutation} cleanup mutation(s), and scheduler loop ${bundle.backgroundProtection.coordinator.schedulerLoopCount}.`);
} catch (error) {
  console.error(`FAIL: ${error.message}`);
  if (serverStderr.trim()) console.error(`Server stderr:\n${serverStderr.trim()}`);
  if (browserStderr.trim()) console.error(`Browser stderr:\n${browserStderr.trim()}`);
  process.exitCode = 1;
} finally {
  let teardownFailure = null;
  try { socket?.close(); } catch {}
  try { await stopChildProcess(browser, "Chromium"); } catch (error) { teardownFailure ??= error; }
  try { await stopChildProcess(server, "Email Shield server"); } catch (error) { teardownFailure ??= error; }
  for (const directory of [browserProfile, downloadDir, dataDir]) {
    try {
      rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    } catch (error) {
      teardownFailure ??= error;
    }
  }
  if (teardownFailure) {
    console.error(`FAIL: Support Bundle teardown did not release its temporary resources: ${teardownFailure.message}`);
    process.exitCode = 1;
  }
}