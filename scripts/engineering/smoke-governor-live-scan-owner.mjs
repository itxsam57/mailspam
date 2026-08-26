import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { waitForDevToolsPort } from "./chromium-devtools-port.mjs";

const root = process.cwd();
const host = "127.0.0.1";
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-governor-live-owner-data-"));
const browserProfile = mkdtempSync(join(tmpdir(), "email-shield-governor-live-owner-profile-"));
let server;
let browser;
let serverStderr = "";
let browserStderr = "";
let socket;

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
      if (response.ok) return response;
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
  throw new Error("No Chrome, Chromium, or Edge executable was found for the live scan owner gate.");
}

async function connectWebSocket(url, timeoutMs = 10_000) {
  return await new Promise((resolveSocket, reject) => {
    const candidate = new WebSocket(url);
    const timer = setTimeout(() => reject(new Error(`Timed out connecting to DevTools: ${url}`)), timeoutMs);
    candidate.addEventListener("open", () => {
      clearTimeout(timer);
      resolveSocket(candidate);
    }, { once: true });
    candidate.addEventListener("error", () => {
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
  throw new Error("Live scan owner gate could not reach the initialized dashboard.");
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

async function waitForFakeSource(client, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ready = await evaluate(client, `Boolean(window.__governorOwnerSource)`).catch(() => false);
    if (ready) return;
    await sleep(50);
  }
  throw new Error("Scan monitor did not create the controlled EventSource.");
}

const scanId = "governor-live-owner-scan";
const token = "governor-live-owner-token";
const summary = {
  verdict: "review",
  score: 7,
  subject: "Governor live ownership regression",
  fromAddress: "owner-test@example.invalid",
  fromDomain: "example.invalid",
  parseStatus: "ok",
  evidenceCodes: ["GOVERNOR_LIVE_OWNER"],
  parseNotes: [],
  decisionNotes: ["Deterministic browser ownership regression vector."],
  reviewAction: {
    token,
    alreadyApproved: false,
    senderTrusted: false,
    canReportSpam: true,
  },
  unsubscribeAction: {
    available: false,
    token: "",
    actionKey: "",
    method: "none",
    alreadyUnsubscribed: false,
  },
};

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
  assert(target?.webSocketDebuggerUrl, "Live scan owner gate found no browser page target.");

  socket = await connectWebSocket(target.webSocketDebuggerUrl);
  const client = createClient(socket);
  await Promise.all([client.send("Page.enable"), client.send("Runtime.enable")]);
  const navigation = await client.send("Page.navigate", { url: `${baseUrl}/?developer=1` }, 15_000);
  assert(!navigation.errorText, `Browser navigation failed: ${navigation.errorText}`);
  await waitForDashboard(client);

  const accountA = await connectFixture(client, "gmail", "governor-live-owner-a");
  const accountB = await connectFixture(client, "icloud", "governor-live-owner-b");
  assert(accountA !== accountB, "Live owner fixture accounts unexpectedly shared an ID.");
  await selectAndWait(client, accountA);

  await evaluate(client, `(() => {
    window.__governorNativeEventSource = window.EventSource;
    class GovernorControlledEventSource {
      static CONNECTING = 0;
      static OPEN = 1;
      static CLOSED = 2;
      constructor(url) {
        this.url = String(url);
        this.readyState = GovernorControlledEventSource.OPEN;
        this.listeners = new Map();
        this.onmessage = null;
        this.onerror = null;
        window.__governorOwnerSource = this;
      }
      addEventListener(type, listener) {
        const bucket = this.listeners.get(type) || [];
        bucket.push(listener);
        this.listeners.set(type, bucket);
      }
      close() {
        this.readyState = GovernorControlledEventSource.CLOSED;
      }
      emit(type, value) {
        const event = { data: JSON.stringify(value) };
        for (const listener of this.listeners.get(type) || []) listener.call(this, event);
        if (type === 'message' && typeof this.onmessage === 'function') this.onmessage.call(this, event);
      }
    }
    window.EventSource = GovernorControlledEventSource;
    return true;
  })()`);

  await evaluate(client, `document.getElementById('fullScanBtn')?.click()`);
  await waitForFakeSource(client);
  await evaluate(client, `window.__governorOwnerSource.emit('scan-started', ${JSON.stringify({ scanId, resumed: false, counters: { examined: 0 } })})`);

  const ownerBeforeSwitch = await evaluate(client, `window.emailShieldScanMonitorOwnership?.ownsLiveScan?.(${JSON.stringify(accountA)}, ${JSON.stringify(scanId)}) === true`);
  assert(ownerBeforeSwitch === true, "Scan monitor did not claim the controlled live scan.");

  await selectAndWait(client, accountB);
  await evaluate(client, `window.__governorOwnerSource.emit('message', ${JSON.stringify({
    counters: { examined: 11, safe: 0, review: 1, highRisk: 0, confirmedThreat: 0, unknown: 0 },
    diagnosticSummaries: [summary],
    suspiciousCards: [],
  })})`);
  const whileAway = await evaluate(client, `(() => ({
    selected: window.emailShieldAccountSelection?.currentId?.() || null,
    tokenRows: document.querySelectorAll('[data-message-row="true"][data-review-token="${token}"]').length,
  }))()`);
  assert(whileAway.selected === accountB, `Mailbox B did not remain selected: ${JSON.stringify(whileAway)}`);
  assert(whileAway.tokenRows === 0, `Live scan rendered into the wrong mailbox while away: ${JSON.stringify(whileAway)}`);

  await selectAndWait(client, accountA);
  const generation = await evaluate(client, `window.emailShieldAccountSelection?.generation?.() ?? null`);
  assert(Number.isInteger(generation), `Account-A generation was unavailable after return: ${generation}`);

  await evaluate(client, `(() => {
    const originalFetch = window.fetch.bind(window);
    window.__governorOwnerOriginalFetch = originalFetch;
    window.fetch = async (...args) => {
      const url = typeof args[0] === 'string' ? args[0] : args[0]?.url || '';
      if (url === '/api/accounts/workspace') {
        return new Response(JSON.stringify({
          selectedAccountId: ${JSON.stringify(accountA)},
          presentation: ${JSON.stringify({
            scanId,
            type: "full",
            status: "running",
            counters: { examined: 22, safe: 0, review: 1, highRisk: 0, confirmedThreat: 0, unknown: 0 },
            diagnosticSummaries: [summary],
            suspiciousCards: [],
            updatedAt: Date.now(),
          })},
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      return originalFetch(...args);
    };
    window.dispatchEvent(new CustomEvent('email-shield-account-selection-settled', {
      detail: { accountId: ${JSON.stringify(accountA)}, generation: ${generation} },
    }));
    return true;
  })()`);
  await sleep(150);

  const afterReattachAttempt = await evaluate(client, `(() => {
    const summaryText = document.querySelector('#scanDiagnosticAudit summary')?.textContent || '';
    return {
      status: document.getElementById('scanMonitorStatus')?.textContent || '',
      tokenRows: document.querySelectorAll('[data-message-row="true"][data-review-token="${token}"]').length,
      diagnosticCount: Number(summaryText.match(/\\((\\d+)\\)/)?.[1] || 0),
      owns: window.emailShieldScanMonitorOwnership?.ownsLiveScan?.(${JSON.stringify(accountA)}, ${JSON.stringify(scanId)}) === true,
    };
  })()`);
  assert(afterReattachAttempt.owns === true, `Live monitor ownership was lost on A -> B -> A return: ${JSON.stringify(afterReattachAttempt)}`);
  assert(afterReattachAttempt.tokenRows === 0 && afterReattachAttempt.diagnosticCount === 0,
    `Detached-document reattach stole the live presentation before the next stream event: ${JSON.stringify(afterReattachAttempt)}`);
  assert(!/Reattached/i.test(afterReattachAttempt.status),
    `Detached-document reattach overwrote the live monitor status: ${JSON.stringify(afterReattachAttempt)}`);

  await evaluate(client, `window.__governorOwnerSource.emit('message', ${JSON.stringify({
    counters: { examined: 23, safe: 0, review: 1, highRisk: 0, confirmedThreat: 0, unknown: 0 },
    diagnosticSummaries: [summary],
    suspiciousCards: [],
  })})`);

  const finalState = await evaluate(client, `(() => {
    const summaryText = document.querySelector('#scanDiagnosticAudit summary')?.textContent || '';
    return {
      selected: window.emailShieldAccountSelection?.currentId?.() || null,
      status: document.getElementById('scanMonitorStatus')?.textContent || '',
      tokenRows: document.querySelectorAll('[data-message-row="true"][data-review-token="${token}"]').length,
      diagnosticCount: Number(summaryText.match(/\\((\\d+)\\)/)?.[1] || 0),
    };
  })()`);
  assert(finalState.selected === accountA, `Account A was not selected at final live render: ${JSON.stringify(finalState)}`);
  assert(finalState.tokenRows === 1 && finalState.diagnosticCount === 1,
    `Live progress was duplicated after A -> B -> A return: ${JSON.stringify(finalState)}`);
  assert(/23 messages examined/i.test(finalState.status) && !/Reattached/i.test(finalState.status),
    `Live monitor did not resume authoritative progress after return: ${JSON.stringify(finalState)}`);

  await evaluate(client, `(() => {
    window.__governorOwnerSource.emit('scan-complete', {});
    if (window.__governorOwnerOriginalFetch) window.fetch = window.__governorOwnerOriginalFetch;
    if (window.__governorNativeEventSource) window.EventSource = window.__governorNativeEventSource;
    return true;
  })()`);

  console.log(`PASS: #131 one live scan owner survives A -> B -> A with no duplicate row/token (${executable}).`);
} catch (error) {
  console.error(`FAIL: ${error instanceof Error ? error.message : String(error)}`);
  if (serverStderr.trim()) console.error(`Server stderr:\n${serverStderr.trim()}`);
  if (browserStderr.trim()) console.error(`Browser stderr:\n${browserStderr.trim()}`);
  process.exitCode = 1;
} finally {
  try { socket?.close(); } catch {}
  await stopChild(browser);
  await stopChild(server);
  rmSync(dataDir, { recursive: true, force: true });
  rmSync(browserProfile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
}