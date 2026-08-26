import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { waitForDevToolsPort } from "./chromium-devtools-port.mjs";

const root = process.cwd();
const host = "127.0.0.1";
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-governor-isolated-data-"));
const browserProfile = mkdtempSync(join(tmpdir(), "email-shield-governor-isolated-profile-"));
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
  throw new Error("No Chrome, Chromium, or Edge executable was found.");
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

async function waitForDashboard(client, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ready = await evaluate(client, `Boolean(
      document.readyState === 'complete' &&
      window.emailShieldSecureFetchInstalled === true &&
      window.emailShieldAccountSelection?.capture &&
      typeof window.emailShieldSelectAccount === 'function' &&
      document.getElementById('fullScanBtn')
    )`).catch(() => false);
    if (ready) return;
    await sleep(100);
  }
  throw new Error("Isolated Governor page did not initialize.");
}

async function pageClient(debugPort, url) {
  const response = await fetch(`http://${host}:${debugPort}/json/new?${encodeURIComponent(url)}`, {
    method: "PUT",
    signal: AbortSignal.timeout(5_000),
  });
  assert(response.ok, `Could not create browser target: HTTP ${response.status}`);
  const target = await response.json();
  const socket = await connectWebSocket(target.webSocketDebuggerUrl);
  const client = createClient(socket);
  await Promise.all([client.send("Page.enable"), client.send("Runtime.enable")]);
  await waitForDashboard(client);
  return client;
}

async function connectFixture(client, label) {
  return await evaluate(client, `(async () => {
    const response = await fetch('/api/accounts/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'gmail', mode: 'fixture', label: ${JSON.stringify(label)} }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || typeof body.accountId !== 'string') throw new Error(body.error || 'Fixture connect failed.');
    await refreshAccounts();
    window.emailShieldSelectAccount(body.accountId);
    window.emailShieldNavigate('scan', { focus: false });
    return body.accountId;
  })()`, 20_000);
}

async function selectAccount(client, id) {
  await evaluate(client, `(async () => {
    window.emailShieldSelectAccount(${JSON.stringify(id)});
    await new Promise((resolveWait) => setTimeout(resolveWait, 0));
    window.emailShieldNavigate('scan', { focus: false });
    return true;
  })()`);
}

async function fullScanForActions(client, accountId, timeoutMs = 30_000) {
  await selectAccount(client, accountId);
  await evaluate(client, `document.getElementById('fullScanBtn')?.click()`);
  const deadline = Date.now() + timeoutMs;
  let state = null;
  while (Date.now() < deadline) {
    state = await evaluate(client, `(() => ({
      busy: document.getElementById('scanPanel')?.getAttribute('aria-busy') === 'true',
      status: document.getElementById('scanMonitorStatus')?.textContent || '',
      unsubscribeToken: document.querySelector('[data-action="unsubscribe"][data-unsubscribe-method="one_click_post"]')?.dataset.unsubscribeToken || null,
      markSafeToken: [...document.querySelectorAll('[data-action="mark-safe"][data-review-token]')].find((button) => !button.disabled)?.dataset.reviewToken || null,
    }))()`);
    if (!state?.busy && state?.unsubscribeToken && state?.markSafeToken) return state;
    await sleep(100);
  }
  throw new Error(`Fixture scan did not expose expected action capabilities: ${JSON.stringify(state)}`);
}

const failures = [];
async function check(name, operation) {
  try {
    await operation();
    console.log(`PASS: ${name}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    failures.push(`${name}: ${message}`);
    console.error(`FAIL: ${name}: ${message}`);
  }
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

  await check("#133 mailto fallback stays in-app, copyable and unconfirmed", async () => {
    const client = await pageClient(debugPort, `${baseUrl}/?developer=1`);
    const accountId = await connectFixture(client, "governor-mailto");
    await selectAccount(client, accountId);

    const setup = await evaluate(client, `(() => {
      const host = document.getElementById('cards');
      if (!(host instanceof HTMLElement)) throw new Error('Cards host missing.');
      const card = document.createElement('article');
      card.className = 'card';
      card.innerHTML = '<div class="card-subject">Controlled newsletter</div><div class="card-from">sender@example.invalid</div><div class="card-actions"><button type="button" data-action="unsubscribe" data-unsubscribe-token="governor-mailto-token" data-unsubscribe-key="governor-mailto-key" data-unsubscribe-method="mailto">Prepare unsubscribe email (not confirmed)</button></div>';
      host.prepend(card);
      window.confirm = () => true;
      window.__governorMailtoTrace = [];
      window.__governorCopiedDraft = '';
      try {
        Object.defineProperty(navigator, 'clipboard', {
          configurable: true,
          value: { writeText: async (value) => { window.__governorCopiedDraft = String(value); } },
        });
      } catch {}
      const originalFetch = window.fetch.bind(window);
      window.fetch = async (...args) => {
        const url = typeof args[0] === 'string' ? args[0] : args[0]?.url || '';
        if (url.includes('/messages/unsubscribe')) {
          window.__governorMailtoTrace.push({ kind: 'unsubscribe', url });
          return new Response(JSON.stringify({
            success: true,
            accountId: ${JSON.stringify(accountId)},
            actionKey: 'governor-mailto-key',
            manualAction: true,
            method: 'mailto',
            target: 'mailto:unsubscribe@example.invalid?subject=Unsubscribe&body=Please%20unsubscribe%20this%20address',
          }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
        if (url.includes('/unsubscribe-activity')) window.__governorMailtoTrace.push({ kind: 'activity', url });
        return originalFetch(...args);
      };
      const button = card.querySelector('button');
      const href = location.href;
      button.click();
      return { href };
    })()`);

    const deadline = Date.now() + 10_000;
    let state = null;
    while (Date.now() < deadline) {
      state = await evaluate(client, `(() => {
        const button = document.querySelector('[data-unsubscribe-token="governor-mailto-token"]');
        return {
          action: button?.dataset.action || '',
          text: button?.textContent || '',
          href: location.href,
          status: button?.closest('.card')?.querySelector('.unsubscribe-action-status')?.textContent || '',
          trace: window.__governorMailtoTrace || [],
        };
      })()`);
      if (state?.action === 'copy-unsubscribe-email') break;
      await sleep(50);
    }
    assert(state?.action === "copy-unsubscribe-email", `mailto fallback did not become in-app copy action: ${JSON.stringify(state)}`);
    assert(state.href === setup.href, `mailto fallback navigated away: ${JSON.stringify(state)}`);
    assert(/Nothing was opened automatically/i.test(state.status), `mailto fallback did not disclose manual state: ${JSON.stringify(state)}`);
    assert(state.trace.filter((item) => item.kind === "unsubscribe").length === 1, `mailto fallback resolve count wrong: ${JSON.stringify(state.trace)}`);
    assert(!state.trace.some((item) => item.kind === "activity"), `mailto fallback falsely recorded Activity: ${JSON.stringify(state.trace)}`);
    await evaluate(client, `document.querySelector('[data-unsubscribe-token="governor-mailto-token"]')?.click()`);
    const copied = await evaluate(client, `window.__governorCopiedDraft || ''`);
    assert(/To: unsubscribe@example\.invalid/.test(copied), `Copied draft lost recipient: ${JSON.stringify(copied)}`);
    assert(/Subject: Unsubscribe/.test(copied), `Copied draft lost subject: ${JSON.stringify(copied)}`);
  });

  await check("two-tab action capability cannot mutate the other mailbox", async () => {
    const tabA = await pageClient(debugPort, `${baseUrl}/?developer=1`);
    const accountA = await connectFixture(tabA, "governor-stale-a");
    const scanA = await fullScanForActions(tabA, accountA);
    const tokenA = scanA.markSafeToken;
    assert(tokenA, "Tab A produced no Mark Safe token.");

    const tabB = await pageClient(debugPort, `${baseUrl}/?developer=1`);
    const accountB = await connectFixture(tabB, "governor-stale-b");
    const baselineB = await evaluate(tabB, `(async () => {
      const response = await fetch('/api/accounts/${accountB}/personal-policy', { cache: 'no-store' });
      const policy = await response.json();
      return Array.isArray(policy.approvedExceptions) ? policy.approvedExceptions.length : -1;
    })()`);

    await selectAccount(tabA, accountA);
    const resultA = await evaluate(tabA, `(async () => {
      const response = await fetch('/api/accounts/${accountA}/messages/mark-safe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: ${JSON.stringify(tokenA)} }),
      });
      return { status: response.status, body: await response.json().catch(() => ({})) };
    })()`);
    assert(resultA.status === 200 && resultA.body?.accountId === accountA && resultA.body?.markedSafe === true,
      `Tab A capability did not settle on A: ${JSON.stringify(resultA)}`);

    const replayOnB = await evaluate(tabB, `(async () => {
      const response = await fetch('/api/accounts/${accountB}/messages/mark-safe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: ${JSON.stringify(tokenA)} }),
      });
      return { status: response.status, body: await response.json().catch(() => ({})) };
    })()`);
    assert(replayOnB.status >= 400, `A token was accepted against B: ${JSON.stringify(replayOnB)}`);

    const afterB = await evaluate(tabB, `(async () => {
      const response = await fetch('/api/accounts/${accountB}/personal-policy', { cache: 'no-store' });
      const policy = await response.json();
      return Array.isArray(policy.approvedExceptions) ? policy.approvedExceptions.length : -1;
    })()`);
    assert(afterB === baselineB, `Tab A token changed B policy: ${JSON.stringify({ baselineB, afterB })}`);
    assert(await evaluate(tabA, `window.emailShieldAccountSelection.currentId()`) === accountA, "Tab A silently changed selection.");
    assert(await evaluate(tabB, `window.emailShieldAccountSelection.currentId()`) === accountB, "Tab B silently changed selection.");
  });

  await check("#131 A -> B -> A retains display ownership of the original running scan", async () => {
    const client = await pageClient(debugPort, `${baseUrl}/?developer=1`);
    const accountA = await connectFixture(client, "governor-switch-a");
    const accountB = await connectFixture(client, "governor-switch-b");
    await selectAccount(client, accountA);

    const installed = await evaluate(client, `(() => {
      const NativeEventSource = window.EventSource;
      class GovernorFakeEventSource {
        constructor(url) {
          this.url = String(url);
          this.listeners = new Map();
          this.onmessage = null;
          this.onerror = null;
          this.closed = false;
          window.__governorSwitchSource = this;
        }
        addEventListener(type, listener) {
          const bucket = this.listeners.get(type) || [];
          bucket.push(listener);
          this.listeners.set(type, bucket);
        }
        emit(type, data) {
          const event = { data: JSON.stringify(data) };
          for (const listener of this.listeners.get(type) || []) listener(event);
          if (type === 'message' && typeof this.onmessage === 'function') this.onmessage(event);
        }
        close() { this.closed = true; }
      }
      GovernorFakeEventSource.CONNECTING = NativeEventSource.CONNECTING;
      GovernorFakeEventSource.OPEN = NativeEventSource.OPEN;
      GovernorFakeEventSource.CLOSED = NativeEventSource.CLOSED;
      window.EventSource = GovernorFakeEventSource;
      return window.EventSource === GovernorFakeEventSource;
    })()`);
    assert(installed === true, "Test EventSource could not be installed on the isolated page.");

    await evaluate(client, `document.getElementById('fullScanBtn')?.click()`);
    const deadline = Date.now() + 10_000;
    let ready = false;
    while (Date.now() < deadline) {
      ready = await evaluate(client, `Boolean(window.__governorSwitchSource)`).catch(() => false);
      if (ready) break;
      await sleep(50);
    }
    assert(ready, "The real scan-monitor did not construct the isolated EventSource.");

    await evaluate(client, `window.__governorSwitchSource.emit('scan-status', { message: 'governor marker one' })`);
    const first = await evaluate(client, `document.getElementById('scanMonitorStatus')?.textContent || ''`);
    assert(/governor marker one/i.test(first), `Initial scan update was not visible: ${first}`);

    await selectAccount(client, accountB);
    await selectAccount(client, accountA);
    await evaluate(client, `window.__governorSwitchSource.emit('scan-status', { message: 'governor marker two' })`);
    const second = await evaluate(client, `document.getElementById('scanMonitorStatus')?.textContent || ''`);
    assert(/governor marker two/i.test(second), `Returning to A suppressed the original running scan update: ${second}`);
  });

  if (failures.length) throw new Error(`Isolated Governor failures (${failures.length}):\n- ${failures.join("\n- ")}`);
  console.log(`Executable isolated Governor actions passed with ${executable}.`);
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
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
