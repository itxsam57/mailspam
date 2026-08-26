import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { waitForDevToolsPort } from "./chromium-devtools-port.mjs";

const root = process.cwd();
const host = "127.0.0.1";
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-governor-account-return-data-"));
const browserProfile = mkdtempSync(join(tmpdir(), "email-shield-governor-account-return-profile-"));
let server;
let browser;
let serverStderr = "";
let browserStderr = "";
const sockets = [];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
const sleep = (ms) => new Promise((resolveWait) => setTimeout(resolveWait, ms));
const childExited = (child) => !child || child.exitCode !== null || child.signalCode !== null;

async function stopChild(child, timeoutMs = 5_000) {
  if (childExited(child)) return;
  const exited = new Promise((resolveExit) => child.once("exit", resolveExit));
  try { child.kill(); } catch {}
  await Promise.race([exited, sleep(timeoutMs)]);
  if (!childExited(child)) {
    try { child.kill("SIGKILL"); } catch {}
    await Promise.race([exited, sleep(1_000)]);
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

async function waitForHttp(url, child, stderr, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (childExited(child)) throw new Error(`Process exited before ${url} became ready.\n${stderr()}`);
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
  for (const command of process.platform === "win32"
    ? ["chrome.exe", "msedge.exe"]
    : ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge"]) {
    const found = findOnPath(command);
    if (found) return found;
  }
  throw new Error("No Chrome, Chromium, or Edge executable was found for the Governor account-return gate.");
}

async function connectWebSocket(url, timeoutMs = 10_000) {
  return await new Promise((resolveSocket, reject) => {
    const socket = new WebSocket(url);
    const timer = setTimeout(() => reject(new Error(`Timed out connecting to DevTools: ${url}`)), timeoutMs);
    socket.addEventListener("open", () => {
      clearTimeout(timer);
      sockets.push(socket);
      resolveSocket(socket);
    }, { once: true });
    socket.addEventListener("error", () => {
      clearTimeout(timer);
      reject(new Error(`Could not connect to DevTools: ${url}`));
    }, { once: true });
  });
}

function createClient(ws) {
  let nextId = 1;
  const pending = new Map();
  ws.addEventListener("message", (event) => {
    let message;
    try { message = JSON.parse(String(event.data)); } catch { return; }
    if (typeof message.id !== "number") return;
    const waiter = pending.get(message.id);
    if (!waiter) return;
    pending.delete(message.id);
    if (message.error) waiter.reject(new Error(`${waiter.method}: ${message.error.message ?? "DevTools error"}`));
    else waiter.resolve(message.result ?? {});
  });
  return {
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

async function waitForDashboard(client, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ready = await evaluate(client, `Boolean(
      document.readyState === 'complete' &&
      window.emailShieldSecureFetchInstalled === true &&
      window.emailShieldAccountSelection?.capture &&
      typeof window.emailShieldSelectAccount === 'function' &&
      document.getElementById('fullScanBtn') &&
      document.getElementById('scanDiagnosticAudit')
    )`).catch(() => false);
    if (ready) return;
    await sleep(100);
  }
  throw new Error("Governor account-return page did not initialize.");
}

async function newPageClient(debugPort, url) {
  const response = await fetch(`http://${host}:${debugPort}/json/new?${encodeURIComponent(url)}`, {
    method: "PUT",
    signal: AbortSignal.timeout(5_000),
  });
  assert(response.ok, `Could not create browser target: HTTP ${response.status}`);
  const target = await response.json();
  assert(target?.webSocketDebuggerUrl, "Browser target did not expose a DevTools socket.");
  const socket = await connectWebSocket(target.webSocketDebuggerUrl);
  const client = createClient(socket);
  await Promise.all([client.send("Page.enable"), client.send("Runtime.enable")]);
  await waitForDashboard(client);
  return client;
}

async function connectFixture(client, provider, label) {
  return await evaluate(client, `(async () => {
    const response = await fetch('/api/accounts/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: ${JSON.stringify(provider)}, mode: 'fixture', label: ${JSON.stringify(label)} }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || typeof body.accountId !== 'string') throw new Error(body.error || 'Fixture connect failed.');
    await refreshAccounts();
    return body.accountId;
  })()`, 20_000);
}

async function selectAndWait(client, accountId, timeoutMs = 10_000) {
  await evaluate(client, `(() => {
    window.emailShieldSelectAccount(${JSON.stringify(accountId)});
    window.emailShieldNavigate('scan', { focus: false });
    return true;
  })()`);
  const deadline = Date.now() + timeoutMs;
  let state = null;
  while (Date.now() < deadline) {
    state = await evaluate(client, `(async () => {
      const response = await fetch('/api/accounts/workspace', { headers: { Accept: 'application/json' }, cache: 'no-store' });
      const workspace = await response.json().catch(() => ({}));
      return {
        local: window.emailShieldAccountSelection?.currentId?.() || null,
        workspace: workspace?.selectedAccountId || null,
      };
    })()`);
    if (state?.local === accountId && state.workspace === accountId) return state;
    await sleep(50);
  }
  throw new Error(`Account selection did not settle: expected=${accountId}; last=${JSON.stringify(state)}`);
}

async function fullScanToken(client, accountId, timeoutMs = 30_000) {
  await selectAndWait(client, accountId);
  await evaluate(client, `document.getElementById('fullScanBtn')?.click()`);
  const deadline = Date.now() + timeoutMs;
  let state = null;
  while (Date.now() < deadline) {
    state = await evaluate(client, `(() => ({
      busy: document.getElementById('scanPanel')?.getAttribute('aria-busy') === 'true',
      status: document.getElementById('scanMonitorStatus')?.textContent || '',
      token: [...document.querySelectorAll('[data-action="mark-safe"][data-review-token]')]
        .find((button) => !button.disabled)?.dataset.reviewToken || null,
    }))()`);
    if (!state?.busy && state?.token) return state.token;
    await sleep(100);
  }
  throw new Error(`Full scan did not expose a Mark Safe token: ${JSON.stringify(state)}`);
}

async function waitForScanHistoryCompletion(client, accountId, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  let state = null;
  while (Date.now() < deadline) {
    state = await evaluate(client, `(async () => {
      const response = await fetch('/api/accounts/${accountId}/scan-history', { headers: { Accept: 'application/json' }, cache: 'no-store' });
      const payload = await response.json().catch(() => ({}));
      const records = Array.isArray(payload?.history) ? payload.history : [];
      const record = records[0] || null;
      return {
        ok: response.ok,
        status: record?.status || null,
        examined: Number(record?.counters?.examined || 0),
        scanId: record?.scanId || null,
      };
    })()`);
    if (state?.ok && state.status === 'completed' && state.examined > 0 && state.scanId) return state;
    await sleep(100);
  }
  throw new Error(`Scan did not complete in protected history while another mailbox was selected: ${JSON.stringify(state)}`);
}

async function waitForReturnedPresentation(client, accountId, expectedScanId, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  let state = null;
  while (Date.now() < deadline) {
    state = await evaluate(client, `(async () => {
      const response = await fetch('/api/accounts/workspace', { headers: { Accept: 'application/json' }, cache: 'no-store' });
      const workspace = await response.json().catch(() => ({}));
      const summary = document.querySelector('#scanDiagnosticAudit summary')?.textContent || '';
      const diagnosticCount = Number(summary.match(/\\((\\d+)\\)/)?.[1] || 0);
      return {
        local: window.emailShieldAccountSelection?.currentId?.() || null,
        workspaceSelected: workspace?.selectedAccountId || null,
        workspaceScanId: workspace?.presentation?.scanId || null,
        workspaceStatus: workspace?.presentation?.status || null,
        workspaceExamined: Number(workspace?.presentation?.counters?.examined || 0),
        diagnosticCount,
        statusText: document.getElementById('scanMonitorStatus')?.textContent || '',
      };
    })()`).catch(() => null);
    if (
      state?.local === accountId &&
      state.workspaceSelected === accountId &&
      state.workspaceScanId === expectedScanId &&
      state.workspaceStatus === 'completed' &&
      state.workspaceExamined > 0 &&
      state.diagnosticCount > 0
    ) return state;
    await sleep(100);
  }
  throw new Error(`Returning to the completed mailbox did not hydrate its final Scan view without refresh: ${JSON.stringify(state)}`);
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

  const tabA = await newPageClient(debugPort, `${baseUrl}/?developer=1`);
  const accountA = await connectFixture(tabA, 'gmail', 'governor-gmail-a');
  const accountB = await connectFixture(tabA, 'icloud', 'governor-icloud-b');
  assert(accountA !== accountB, 'Fixture accounts unexpectedly shared a session ID.');

  // Real token/account boundary across two independent browser tabs.
  const tokenA = await fullScanToken(tabA, accountA);
  const tabB = await newPageClient(debugPort, `${baseUrl}/?developer=1`);
  await selectAndWait(tabB, accountB);
  const baselineB = await evaluate(tabB, `(async () => {
    const response = await fetch('/api/accounts/${accountB}/personal-policy', { cache: 'no-store' });
    const policy = await response.json();
    return Array.isArray(policy.approvedExceptions) ? policy.approvedExceptions.length : -1;
  })()`);
  await selectAndWait(tabA, accountA);
  const settleA = await evaluate(tabA, `(async () => {
    const response = await fetch('/api/accounts/${accountA}/messages/mark-safe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: ${JSON.stringify(tokenA)} }),
    });
    return { status: response.status, body: await response.json().catch(() => ({})) };
  })()`);
  assert(
    settleA.status === 200 && settleA.body?.accountId === accountA && settleA.body?.markedSafe === true,
    `Account-A token did not settle on A: ${JSON.stringify(settleA)}`,
  );
  const replayB = await evaluate(tabB, `(async () => {
    const response = await fetch('/api/accounts/${accountB}/messages/mark-safe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: ${JSON.stringify(tokenA)} }),
    });
    return { status: response.status, body: await response.json().catch(() => ({})) };
  })()`);
  assert(replayB.status >= 400, `Account-A token was accepted against account B: ${JSON.stringify(replayB)}`);
  const afterB = await evaluate(tabB, `(async () => {
    const response = await fetch('/api/accounts/${accountB}/personal-policy', { cache: 'no-store' });
    const policy = await response.json();
    return Array.isArray(policy.approvedExceptions) ? policy.approvedExceptions.length : -1;
  })()`);
  assert(afterB === baselineB, `Account-A token changed B policy: ${JSON.stringify({ baselineB, afterB })}`);
  assert(await evaluate(tabA, `window.emailShieldAccountSelection.currentId()`) === accountA, 'Tab A silently changed mailbox selection.');
  assert(await evaluate(tabB, `window.emailShieldAccountSelection.currentId()`) === accountB, 'Tab B silently changed mailbox selection.');
  console.log('PASS: two-tab Gmail/iCloud action token remained account-scoped with no cross-mailbox mutation.');

  // Exact user-visible #131 completed-while-away return path. Start A, leave for B,
  // wait for A to finish in protected history, then return to A without a page refresh.
  await selectAndWait(tabA, accountA);
  await evaluate(tabA, `document.getElementById('fullScanBtn')?.click()`);
  await selectAndWait(tabA, accountB);
  const completedA = await waitForScanHistoryCompletion(tabA, accountA);
  const whileAway = await evaluate(tabA, `(() => ({
    selected: window.emailShieldAccountSelection.currentId(),
    summary: document.querySelector('#scanDiagnosticAudit summary')?.textContent || '',
  }))()`);
  assert(whileAway.selected === accountB, `Mailbox B did not remain selected while A completed: ${JSON.stringify(whileAway)}`);
  await selectAndWait(tabA, accountA);
  const returnedA = await waitForReturnedPresentation(tabA, accountA, completedA.scanId);
  assert(returnedA.workspaceExamined === completedA.examined, `Returned workspace counters diverged from protected A history: ${JSON.stringify({ completedA, returnedA })}`);
  console.log(`PASS: #131 completed Gmail scan hydrated after iCloud -> Gmail return without browser refresh (${returnedA.workspaceExamined} examined).`);

  console.log(`Executable Governor account-return gate passed with ${executable}.`);
} catch (error) {
  console.error(`FAIL: ${error instanceof Error ? error.message : String(error)}`);
  if (serverStderr.trim()) console.error(`Server stderr:\n${serverStderr.trim()}`);
  if (browserStderr.trim()) console.error(`Browser stderr:\n${browserStderr.trim()}`);
  process.exitCode = 1;
} finally {
  for (const socket of sockets) {
    try { socket.close(); } catch {}
  }
  await stopChild(browser);
  await stopChild(server);
  rmSync(dataDir, { recursive: true, force: true });
  rmSync(browserProfile, { recursive: true, force: true });
}
