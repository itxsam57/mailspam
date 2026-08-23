import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = process.cwd();
const host = "127.0.0.1";
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-health-identity-data-"));
const browserProfile = mkdtempSync(join(tmpdir(), "email-shield-health-identity-profile-"));
let server;
let browser;
let socket;
let serverStderr = "";
let browserStderr = "";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const sleep = (ms) => new Promise((resolveWait) => setTimeout(resolveWait, ms));

function childProcessExited(processRef) {
  return !processRef || processRef.exitCode !== null || processRef.signalCode !== null;
}

async function stopChild(processRef, label) {
  if (childProcessExited(processRef)) return;
  try { processRef.kill(); } catch {}
  const gracefulDeadline = Date.now() + 3_000;
  while (!childProcessExited(processRef) && Date.now() < gracefulDeadline) await sleep(50);
  if (childProcessExited(processRef)) return;
  try { processRef.kill("SIGKILL"); } catch {}
  const forcedDeadline = Date.now() + 3_000;
  while (!childProcessExited(processRef) && Date.now() < forcedDeadline) await sleep(50);
  assert(childProcessExited(processRef), `${label} did not exit during Health identity teardown.`);
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

async function waitForDevToolsPort(profileDirectory, processRef, stderr, timeoutMs = 20_000) {
  const activePortPath = join(profileDirectory, "DevToolsActivePort");
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (processRef?.exitCode !== null) throw new Error(`Chromium exited before publishing DevToolsActivePort.\n${stderr()}`);
    try {
      if (existsSync(activePortPath)) {
        const firstLine = readFileSync(activePortPath, "utf8").split(/\r?\n/, 1)[0]?.trim() ?? "";
        const port = Number.parseInt(firstLine, 10);
        if (Number.isInteger(port) && port > 0 && port <= 65_535) return port;
        lastError = new Error(`Invalid DevToolsActivePort value: ${JSON.stringify(firstLine)}`);
      }
    } catch (error) { lastError = error; }
    await sleep(50);
  }
  throw new Error(`Timed out waiting for Chromium DevTools: ${lastError?.message ?? "port unavailable"}`);
}

function findOnPath(command) {
  const result = spawnSync(process.platform === "win32" ? "where" : "which", [command], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  return result.status === 0 ? result.stdout.split(/\r?\n/).map((line) => line.trim()).find(Boolean) ?? null : null;
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
  throw new Error("No Chrome, Chromium, or Edge executable was found for the Health identity gate.");
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
        const timer = setTimeout(() => { pending.delete(id); reject(new Error(`DevTools command timed out: ${method}`)); }, timeoutMs);
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
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description ?? result.exceptionDetails.text ?? "Browser evaluation failed");
  return result.result?.value;
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
      EMAIL_SHIELD_ENABLE_HEALTH_IDENTITY_FIXTURES: "1",
      EMAIL_SHIELD_HEALTH_IDENTITY_FIXTURES_ONLY: "1",
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
  const navigation = await client.send("Page.navigate", { url: `${baseUrl}/?developer=1` }, 15_000);
  assert(!navigation.errorText, `Browser navigation failed: ${navigation.errorText}`);

  const readyDeadline = Date.now() + 15_000;
  let ready = false;
  while (Date.now() < readyDeadline) {
    ready = await evaluate(client, `Boolean(
      document.readyState === 'complete' &&
      window.emailShieldSecureFetchInstalled === true &&
      window.emailShieldInstalledModules?.has('health-cleanup-controller') &&
      typeof window.emailShieldSelectAccount === 'function' &&
      typeof window.emailShieldNavigate === 'function' &&
      document.getElementById('consumerRunHealth')
    )`).catch(() => false);
    if (ready) break;
    await sleep(100);
  }
  assert(ready, "Health identity browser gate could not reach the initialized dashboard.");

  const accountId = await evaluate(client, `(async () => {
    const response = await fetch('/api/accounts/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'gmail', mode: 'fixture', label: 'health-identity-fixture' }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || typeof body.accountId !== 'string') throw new Error(body.error || 'Fixture connection failed.');
    await refreshAccounts();
    window.emailShieldSelectAccount(body.accountId, { remember: false });
    window.emailShieldNavigate('protection', { focus: false });
    document.getElementById('consumerRunHealth').click();
    return body.accountId;
  })()`, 20_000);
  assert(typeof accountId === "string" && accountId, "Health identity fixture account was not created.");

  let before = null;
  const healthDeadline = Date.now() + 35_000;
  while (Date.now() < healthDeadline) {
    before = await evaluate(client, `(() => {
      const subscriptions = [...document.querySelectorAll('#consumerSubscriptions .consumer-list-item')]
        .filter((row) => row.querySelector('strong')?.textContent?.trim() === 'Instagram')
        .map((row) => ({
          text: row.textContent || '',
          key: row.querySelector('button[data-health-cleanup-key]')?.dataset.healthCleanupKey || '',
          old: Number((row.querySelector('.health-cleanup-eligibility')?.textContent || '').match(/(\\d+) message\\(s\\) older than 30 days/)?.[1] || 0),
        }));
      const footprintRows = [...document.querySelectorAll('#consumerFootprint .consumer-list-item')];
      const relay = footprintRows.find((row) => row.querySelector('strong')?.textContent?.trim() === 'privaterelay.appleid.com') || null;
      return {
        subscriptions,
        footprintCount: footprintRows.filter((row) => row.querySelector('strong')?.textContent?.trim() === 'privaterelay.appleid.com').length,
        relayText: relay?.textContent || '',
        allText: document.getElementById('consumerHealthPanel')?.textContent || '',
      };
    })()`);
    if (before?.subscriptions?.length === 2 && before.subscriptions.every((item) => item.key && item.old > 0) && before.footprintCount === 1) break;
    await sleep(100);
  }

  assert(before?.subscriptions?.length === 2, `Expected exactly two visible Instagram subscription identities. State: ${JSON.stringify(before)}`);
  assert(before.subscriptions[0].key !== before.subscriptions[1].key, `Same-name subscription rows did not retain distinct canonical keys. State: ${JSON.stringify(before)}`);
  assert(before.subscriptions.some((item) => /source 1 of 2/i.test(item.text)), `First privacy-safe Instagram differentiator was missing. State: ${JSON.stringify(before)}`);
  assert(before.subscriptions.some((item) => /source 2 of 2/i.test(item.text)), `Second privacy-safe Instagram differentiator was missing. State: ${JSON.stringify(before)}`);
  assert(before.footprintCount === 1, `Private Relay rendered as duplicate top-level footprint services. State: ${JSON.stringify(before)}`);
  assert(/account welcome \(2\)/i.test(before.relayText), `Aggregated welcome evidence count was missing. State: ${JSON.stringify(before)}`);
  assert(/receipt subscription \(1\)/i.test(before.relayText), `Aggregated receipt/subscription evidence count was missing. State: ${JSON.stringify(before)}`);
  assert(!/promotions\.instagram\.fixture|product\.instagram\.fixture/i.test(before.allText), `Raw List-ID leaked into visible Health UI. State: ${JSON.stringify(before)}`);

  const selectedKey = before.subscriptions.find((item) => /source 1 of 2/i.test(item.text))?.key;
  assert(selectedKey, `Could not resolve the visible source 1 cleanup target. State: ${JSON.stringify(before)}`);
  const selectedKeyLiteral = JSON.stringify(selectedKey);
  await evaluate(client, `(() => {
    window.confirm = () => true;
    window.prompt = () => 'MOVE TO TRASH';
    const button = [...document.querySelectorAll('#consumerSubscriptions button[data-health-cleanup-key]')]
      .find((candidate) => candidate.dataset.healthCleanupKey === ${selectedKeyLiteral});
    if (!button) throw new Error('Selected canonical cleanup control disappeared before click.');
    button.click();
    return true;
  })()`);

  let after = null;
  const cleanupDeadline = Date.now() + 40_000;
  while (Date.now() < cleanupDeadline) {
    after = await evaluate(client, `(async () => {
      const subscriptions = [...document.querySelectorAll('#consumerSubscriptions .consumer-list-item')]
        .filter((row) => row.querySelector('strong')?.textContent?.trim() === 'Instagram')
        .map((row) => ({
          text: row.textContent || '',
          key: row.querySelector('button[data-health-cleanup-key]')?.dataset.healthCleanupKey || '',
        }));
      const activityResponse = await fetch('/api/consumer/v1/accounts/${accountId}/activity', { cache: 'no-store' });
      const activityBody = await activityResponse.json().catch(() => ({}));
      const cleanup = Array.isArray(activityBody.activity)
        ? activityBody.activity.find((item) => item?.kind === 'cleanup') || null
        : null;
      return {
        subscriptions,
        cleanupTitle: cleanup?.title || '',
        cleanupDetail: cleanup?.detail || '',
        activityOk: activityResponse.ok,
        status: document.getElementById('consumerHealthStatus')?.textContent || '',
      };
    })()`);
    if (after?.activityOk && after.cleanupTitle && after.subscriptions?.length === 1) break;
    await sleep(100);
  }

  assert(after?.activityOk === true, `Health identity cleanup Activity was unavailable. State: ${JSON.stringify(after)}`);
  assert(after.cleanupTitle === 'Mailbox cleanup completed', `Cleanup Activity did not report a truthful completed mutation. State: ${JSON.stringify(after)}`);
  assert(after.subscriptions.length === 1, `Selected-list cleanup did not preserve exactly one same-sender sibling list. Before: ${JSON.stringify(before)} After: ${JSON.stringify(after)}`);
  assert(after.subscriptions[0].key !== selectedKey, `The selected list still remained after confirmed cleanup. State: ${JSON.stringify(after)}`);
  assert(!/0 matching message\(s\) were moved/i.test(after.cleanupDetail), `Cleanup Activity falsely reported a zero-move success. State: ${JSON.stringify(after)}`);
  assert(runtimeErrors.length === 0, `Health identity acceptance produced uncaught browser errors: ${JSON.stringify(runtimeErrors)}`);

  console.log(`Executable Health identity aggregation smoke passed with ${executable}.`);
  console.log("Two same-name/same-sender Instagram lists rendered distinctly; one selected list was cleaned while its sibling remained.");
  console.log("Private Relay rendered once with account-welcome count 2 and receipt/subscription count 1.");
} catch (error) {
  console.error(`FAIL: ${error.message}`);
  if (serverStderr.trim()) console.error(`Server stderr:\n${serverStderr}`);
  if (browserStderr.trim()) console.error(`Browser stderr:\n${browserStderr}`);
  process.exitCode = 1;
} finally {
  try { socket?.close(); } catch {}
  await stopChild(browser, "Chromium");
  await stopChild(server, "Email Shield server");
  try { rmSync(browserProfile, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 }); } catch {}
  try { rmSync(dataDir, { recursive: true, force: true, maxRetries: 8, retryDelay: 100 }); } catch {}
}
