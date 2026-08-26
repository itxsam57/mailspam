import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { waitForDevToolsPort } from "./chromium-devtools-port.mjs";

const root = process.cwd();
const host = "127.0.0.1";
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-governor-v2-data-"));
const browserProfile = mkdtempSync(join(tmpdir(), "email-shield-governor-v2-profile-"));
let server;
let browser;
let serverStderr = "";
let browserStderr = "";
const sockets = [];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
const sleep = (ms) => new Promise((resolveWait) => setTimeout(resolveWait, ms));

function childExited(processRef) {
  return !processRef || processRef.exitCode !== null || processRef.signalCode !== null;
}

async function stopChild(processRef, timeoutMs = 5_000) {
  if (childExited(processRef)) return;
  const exited = new Promise((resolveExit) => processRef.once("exit", resolveExit));
  try { processRef.kill(); } catch {}
  await Promise.race([exited, sleep(timeoutMs)]);
  if (!childExited(processRef)) {
    try { processRef.kill("SIGKILL"); } catch {}
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

async function waitForHttp(url, processRef, stderr, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (childExited(processRef)) throw new Error(`Process exited before ${url} became ready.\n${stderr()}`);
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(2_000) });
      if (response.ok) return response;
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) { lastError = error; }
    await sleep(100);
  }
  throw new Error(`Timed out waiting for ${url}: ${lastError?.message ?? "unknown error"}\n${stderr()}`);
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
  throw new Error("No Chrome, Chromium, or Edge executable was found for the Governor browser gate.");
}

async function connectWebSocket(url, timeoutMs = 10_000) {
  return await new Promise((resolveSocket, reject) => {
    const candidate = new WebSocket(url);
    const timer = setTimeout(() => reject(new Error(`Timed out connecting to DevTools: ${url}`)), timeoutMs);
    candidate.addEventListener("open", () => {
      clearTimeout(timer);
      sockets.push(candidate);
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
      typeof window.emailShieldSelectAccount === 'function' &&
      typeof window.emailShieldNavigate === 'function' &&
      document.getElementById('fullScanBtn') &&
      document.getElementById('scamCheckPanel')
    )`).catch(() => false);
    if (ready) return;
    await sleep(100);
  }
  throw new Error("Governor browser gate could not reach the initialized dashboard.");
}

function nextMainFrameNavigation(client, timeoutMs = 15_000) {
  return new Promise((resolveNavigation, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error("Timed out waiting for the scan-started forced document reload."));
    }, timeoutMs);
    client.on("Page.frameNavigated", ({ frame }) => {
      if (settled || frame?.parentId) return;
      settled = true;
      clearTimeout(timer);
      resolveNavigation(frame);
    });
  });
}

async function newPageClient(debugPort, url) {
  const response = await fetch(`http://${host}:${debugPort}/json/new?${encodeURIComponent(url)}`, {
    method: "PUT",
    signal: AbortSignal.timeout(5_000),
  });
  if (!response.ok) throw new Error(`Could not create second browser target: HTTP ${response.status}`);
  const target = await response.json();
  assert(target?.webSocketDebuggerUrl, "Second browser target did not expose a DevTools socket.");
  const socket = await connectWebSocket(target.webSocketDebuggerUrl);
  const client = createClient(socket);
  await Promise.all([client.send("Page.enable"), client.send("Runtime.enable")]);
  await waitForDashboard(client);
  return client;
}

async function connectFixtureAccount(client, label) {
  return await evaluate(client, `(async () => {
    const response = await fetch('/api/accounts/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'gmail', mode: 'fixture', label: ${JSON.stringify(label)} }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || typeof body.accountId !== 'string') throw new Error(body.error || 'Fixture account connection failed.');
    await refreshAccounts();
    window.emailShieldSelectAccount(body.accountId);
    window.emailShieldNavigate('scan', { focus: false });
    return body.accountId;
  })()`, 20_000);
}

async function selectAccount(client, accountId) {
  await evaluate(client, `(async () => {
    window.emailShieldSelectAccount(${JSON.stringify(accountId)});
    await new Promise((resolveWait) => setTimeout(resolveWait, 0));
    window.emailShieldNavigate('scan', { focus: false });
    return window.emailShieldAccountSelection?.capture?.() || null;
  })()`);
}

async function waitForCompletedRestoredScan(client, accountId, timeoutMs = 25_000) {
  const deadline = Date.now() + timeoutMs;
  let state = null;
  while (Date.now() < deadline) {
    state = await evaluate(client, `(async () => {
      const response = await fetch('/api/accounts/workspace', { headers: { Accept: 'application/json' }, cache: 'no-store' });
      const workspace = await response.json().catch(() => ({}));
      const summary = document.querySelector('#scanDiagnosticAudit summary')?.textContent || '';
      const diagnosticCount = Number(summary.match(/\\((\\d+)\\)/)?.[1] || 0);
      return {
        selected: window.emailShieldAccountSelection?.currentId?.() || null,
        status: document.getElementById('scanMonitorStatus')?.textContent || '',
        busy: document.getElementById('scanPanel')?.getAttribute('aria-busy') === 'true',
        diagnosticCount,
        workspaceSelected: workspace?.selectedAccountId || null,
        workspaceScanId: workspace?.presentation?.scanId || null,
        workspaceStatus: workspace?.presentation?.status || null,
        workspaceExamined: Number(workspace?.presentation?.counters?.examined || 0),
      };
    })()`).catch(() => null);
    if (
      state?.selected === accountId &&
      state.workspaceSelected === accountId &&
      state.workspaceScanId &&
      state.workspaceStatus === "completed" &&
      state.workspaceExamined > 0 &&
      state.diagnosticCount > 0
    ) return state;
    await sleep(100);
  }
  throw new Error(`Refreshed Scan page did not restore authoritative completed progress: ${JSON.stringify(state)}`);
}

async function runUrlUi(client, value, timeoutMs = 25_000) {
  await evaluate(client, `(() => {
    document.querySelector('[data-scam-check-mode="url"]')?.click();
    const input = document.getElementById('scamCheckUrl');
    if (!(input instanceof HTMLInputElement)) throw new Error('Analyze Links input is missing.');
    input.value = ${JSON.stringify(value)};
    document.getElementById('scamCheckRun')?.click();
    return true;
  })()`);
  const deadline = Date.now() + timeoutMs;
  let state = null;
  while (Date.now() < deadline) {
    state = await evaluate(client, `(() => ({
      running: document.getElementById('scamCheckRun')?.disabled === true,
      hidden: document.getElementById('scamCheckResult')?.hidden === true,
      resultText: document.getElementById('scamCheckResult')?.textContent || '',
      badge: document.querySelector('#scamCheckResult .scam-check-badge')?.textContent || '',
      status: document.getElementById('scamCheckStatus')?.textContent || '',
    }))()`);
    if (!state?.running && !state?.hidden) return state;
    if (!state?.running && /failed|error/i.test(state?.status || '')) {
      throw new Error(`Analyze Links UI failed for ${value}: ${JSON.stringify(state)}`);
    }
    await sleep(100);
  }
  throw new Error(`Analyze Links UI timed out for ${value}. Last state: ${JSON.stringify(state)}`);
}

async function runFreshActionScan(client, accountId, timeoutMs = 25_000) {
  await selectAccount(client, accountId);
  await evaluate(client, `(() => { document.getElementById('fullScanBtn')?.click(); return true; })()`);
  const deadline = Date.now() + timeoutMs;
  let state = null;
  while (Date.now() < deadline) {
    state = await evaluate(client, `(() => {
      const unsubscribe = document.querySelector('[data-action="unsubscribe"][data-unsubscribe-method="one_click_post"]');
      const markSafe = [...document.querySelectorAll('[data-action="mark-safe"][data-review-token]')].find((button) => !button.disabled) || null;
      return {
        unsubscribe: Boolean(unsubscribe),
        markSafe: Boolean(markSafe),
        busy: document.getElementById('scanPanel')?.getAttribute('aria-busy') === 'true',
        status: document.getElementById('scanMonitorStatus')?.textContent || '',
      };
    })()`);
    if (state?.unsubscribe && state.markSafe && !state.busy) return state;
    await sleep(100);
  }
  throw new Error(`Fresh action scan did not expose the expected verified actions: ${JSON.stringify(state)}`);
}

const failures = [];
async function check(name, operation) {
  try {
    const result = await operation();
    console.log(`PASS: ${name}`);
    return result;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    failures.push(`${name}: ${message}`);
    console.error(`FAIL: ${name}: ${message}`);
    return null;
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
  const targets = await (await fetch(`http://${host}:${debugPort}/json/list`, { signal: AbortSignal.timeout(5_000) })).json();
  const target = Array.isArray(targets) ? targets.find((item) => item.type === "page" && item.webSocketDebuggerUrl) : null;
  assert(target?.webSocketDebuggerUrl, "Governor browser exposed no initial page target.");

  const socket = await connectWebSocket(target.webSocketDebuggerUrl);
  const tabA = createClient(socket);
  const runtimeErrors = [];
  tabA.on("Runtime.exceptionThrown", ({ exceptionDetails }) => runtimeErrors.push(
    exceptionDetails?.exception?.description ?? exceptionDetails?.text ?? "browser exception",
  ));
  await Promise.all([tabA.send("Page.enable"), tabA.send("Runtime.enable")]);
  const navigation = await tabA.send("Page.navigate", { url: `${baseUrl}/?developer=1` }, 15_000);
  assert(!navigation.errorText, `Governor browser navigation failed: ${navigation.errorText}`);
  await waitForDashboard(tabA);

  const accountA = await connectFixtureAccount(tabA, "governor-v2-tab-a");

  await check("#131 active scan survives real document refresh and restores authoritative results", async () => {
    await selectAccount(tabA, accountA);
    await evaluate(tabA, `(() => {
      if (window.__governorNativeEventSource) return true;
      const NativeEventSource = window.EventSource;
      window.__governorNativeEventSource = NativeEventSource;
      window.EventSource = class GovernorReloadEventSource extends NativeEventSource {
        constructor(url, options) {
          super(url, options);
          if (String(url).includes('/scan/')) {
            this.addEventListener('scan-started', () => {
              setTimeout(() => window.location.reload(), 0);
            }, { once: true });
          }
        }
      };
      return true;
    })()`);
    const reloaded = nextMainFrameNavigation(tabA);
    const immediate = await evaluate(tabA, `(() => {
      document.getElementById('fullScanBtn')?.click();
      return {
        busy: document.getElementById('scanPanel')?.getAttribute('aria-busy') === 'true',
        selected: window.emailShieldAccountSelection?.currentId?.() || null,
        status: document.getElementById('scanMonitorStatus')?.textContent || '',
      };
    })()`);
    assert(immediate?.busy === true && immediate.selected === accountA, `Full scan did not synchronously enter the selected-account running state: ${JSON.stringify(immediate)}`);
    await reloaded;
    await waitForDashboard(tabA);
    const restored = await waitForCompletedRestoredScan(tabA, accountA);
    assert(restored.workspaceExamined > 0 && restored.diagnosticCount > 0, `Refresh restored no authoritative results: ${JSON.stringify(restored)}`);
  });

  await check("#132 Analyze Links distinguishes HTTPS, HTTP, deceptive reserved URLs and whole encoded URLs", async () => {
    const httpsResult = await runUrlUi(tabA, "https://example.com");
    const httpResult = await runUrlUi(tabA, "http://example.com");
    assert(!/unencrypted HTTP transport/i.test(httpsResult.resultText), `HTTPS was mislabeled as unencrypted HTTP: ${httpsResult.resultText}`);
    assert(/HTTPS transport/i.test(httpsResult.resultText), `HTTPS transport truth was missing from the visible result: ${httpsResult.resultText}`);
    assert(/unencrypted HTTP transport/i.test(httpResult.resultText), `HTTP transport weakness was missing from the visible result: ${httpResult.resultText}`);
    assert(httpResult.resultText !== httpsResult.resultText, "HTTP and HTTPS still rendered as identical Analyze Links results.");

    const deceptiveResult = await runUrlUi(tabA, "http://paypal-login.example.invalid/verify-account");
    assert(/unencrypted HTTP transport/i.test(deceptiveResult.resultText), `Reserved deceptive URL lost HTTP evidence: ${deceptiveResult.resultText}`);
    assert(/subdomain combines an identity-like label/i.test(deceptiveResult.resultText), `Reserved deceptive URL lost identity/action subdomain evidence: ${deceptiveResult.resultText}`);
    assert(/destination path combines multiple account/i.test(deceptiveResult.resultText), `Reserved deceptive URL lost sensitive account-path evidence: ${deceptiveResult.resultText}`);
    assert(deceptiveResult.badge.trim().toLowerCase() === "review", `Reserved deceptive URL did not render Review: ${JSON.stringify(deceptiveResult)}`);

    const encodedResult = await runUrlUi(tabA, "https%3A%2F%2Fshop.example%2Faccount%3Fmode%3Dreview");
    assert(!/could not be parsed as a valid URL|MALFORMED_URL/i.test(encodedResult.resultText), `Whole percent-encoded URL still rendered malformed evidence: ${encodedResult.resultText}`);
  });

  await check("#133 mailto unsubscribe fallback stays in-app and never claims completion", async () => {
    await runFreshActionScan(tabA, accountA);
    const mailtoSetup = await evaluate(tabA, `(() => {
      const button = document.querySelector('[data-action="unsubscribe"][data-unsubscribe-method="one_click_post"]');
      if (!(button instanceof HTMLButtonElement)) return null;
      const accountId = window.emailShieldAccountSelection?.currentId?.() || null;
      const actionKey = button.dataset.unsubscribeKey || '';
      const token = button.dataset.unsubscribeToken || '';
      if (!accountId || !actionKey || !token) return null;
      button.dataset.unsubscribeMethod = 'mailto';
      button.textContent = 'Prepare unsubscribe email (not confirmed)';
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
            accountId,
            actionKey,
            manualAction: true,
            method: 'mailto',
            target: 'mailto:unsubscribe@example.invalid?subject=Unsubscribe&body=Please%20unsubscribe%20this%20address',
          }), { status: 200, headers: { 'Content-Type': 'application/json' } });
        }
        if (url.includes('/unsubscribe-activity')) window.__governorMailtoTrace.push({ kind: 'activity', url });
        return originalFetch(...args);
      };
      return { accountId, actionKey, token, href: location.href };
    })()`);
    assert(mailtoSetup, "No verified unsubscribe button was available for the mailto UI branch test.");

    await evaluate(tabA, `(() => {
      const button = document.querySelector('[data-unsubscribe-token="${mailtoSetup.token}"]');
      if (!(button instanceof HTMLButtonElement)) throw new Error('Controlled unsubscribe button disappeared.');
      button.click();
      return true;
    })()`);

    const deadline = Date.now() + 10_000;
    let state = null;
    while (Date.now() < deadline) {
      state = await evaluate(tabA, `(() => {
        const button = document.querySelector('[data-unsubscribe-token="${mailtoSetup.token}"]');
        return {
          action: button?.dataset.action || '',
          text: button?.textContent || '',
          href: location.href,
          status: button?.closest('.card,[data-message-row="true"]')?.querySelector('.unsubscribe-action-status')?.textContent || '',
          trace: window.__governorMailtoTrace || [],
        };
      })()`);
      if (state?.action === 'copy-unsubscribe-email') break;
      await sleep(100);
    }
    assert(state?.action === "copy-unsubscribe-email", `mailto fallback did not remain in-app: ${JSON.stringify(state)}`);
    assert(state.href === mailtoSetup.href, `mailto fallback changed browser location instead of staying in-app: ${JSON.stringify(state)}`);
    assert(/Nothing was opened automatically/i.test(state.status), `mailto fallback did not truthfully explain the in-app state: ${JSON.stringify(state)}`);
    assert(state.trace.filter((item) => item.kind === "unsubscribe").length === 1, `mailto fallback did not make exactly one protected resolve request: ${JSON.stringify(state.trace)}`);
    assert(state.trace.some((item) => item.kind === "activity") === false, `mailto preparation falsely wrote Activity: ${JSON.stringify(state.trace)}`);

    await evaluate(tabA, `document.querySelector('[data-unsubscribe-token="${mailtoSetup.token}"]')?.click()`);
    const copiedDraft = await evaluate(tabA, `window.__governorCopiedDraft || ''`);
    assert(/To: unsubscribe@example\.invalid/i.test(copiedDraft), `mailto copy action did not produce the bounded recipient draft: ${JSON.stringify(copiedDraft)}`);
    assert(/Subject: Unsubscribe/i.test(copiedDraft), `mailto copy action lost the bounded subject: ${JSON.stringify(copiedDraft)}`);
  });

  let tabB = null;
  let accountB = null;
  await check("two-tab stale action remains account-scoped", async () => {
    await runFreshActionScan(tabA, accountA);
    tabB = await newPageClient(debugPort, `${baseUrl}/?developer=1`);
    accountB = await connectFixtureAccount(tabB, "governor-v2-tab-b");
    const baselineB = await evaluate(tabB, `(async () => {
      const response = await fetch('/api/accounts/${accountB}/personal-policy', { cache: 'no-store' });
      const body = await response.json();
      return Array.isArray(body.approvedExceptions) ? body.approvedExceptions.length : -1;
    })()`);

    await selectAccount(tabA, accountA);
    const staleAction = await evaluate(tabA, `(() => {
      const button = [...document.querySelectorAll('[data-action="mark-safe"][data-review-token]')]
        .find((candidate) => !candidate.disabled);
      if (!button) return null;
      window.confirm = () => true;
      const token = button.dataset.reviewToken || '';
      button.click();
      return token;
    })()`);
    assert(staleAction, "Tab A had no harmless Mark Safe action for stale-tab isolation.");

    const deadline = Date.now() + 10_000;
    let isolation = null;
    while (Date.now() < deadline) {
      isolation = await evaluate(tabA, `(async () => {
        const [aResponse, bResponse] = await Promise.all([
          fetch('/api/accounts/${accountA}/personal-policy', { cache: 'no-store' }),
          fetch('/api/accounts/${accountB}/personal-policy', { cache: 'no-store' }),
        ]);
        const a = await aResponse.json();
        const b = await bResponse.json();
        return {
          aCount: Array.isArray(a.approvedExceptions) ? a.approvedExceptions.length : -1,
          bCount: Array.isArray(b.approvedExceptions) ? b.approvedExceptions.length : -1,
          tabASelection: window.emailShieldAccountSelection?.currentId?.() || null,
        };
      })()`);
      if (isolation?.aCount > 0) break;
      await sleep(100);
    }
    const tabBSelection = await evaluate(tabB, `window.emailShieldAccountSelection?.currentId?.() || null`);
    assert(isolation?.aCount > 0, `Tab A harmless action did not settle on its own mailbox: ${JSON.stringify(isolation)}`);
    assert(isolation.bCount === baselineB, `Tab A stale action leaked into Tab B mailbox policy: ${JSON.stringify({ baselineB, isolation })}`);
    assert(isolation.tabASelection === accountA, `Tab A silently switched mailbox ownership: ${JSON.stringify(isolation)}`);
    assert(tabBSelection === accountB, `Tab B selection was changed by Tab A action: ${JSON.stringify({ tabBSelection, accountB })}`);
  });

  await check("#131 running scan resumes visible updates after A -> B -> A account return", async () => {
    if (!accountB) accountB = await connectFixtureAccount(tabA, "governor-v2-switch-b");
    await selectAccount(tabA, accountA);
    await evaluate(tabA, `(() => {
      const NativeEventSource = window.EventSource;
      class FakeEventSource {
        constructor(url) {
          this.url = String(url);
          this.listeners = new Map();
          this.onmessage = null;
          this.closed = false;
          window.__governorFakeScanSource = this;
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
      FakeEventSource.CONNECTING = NativeEventSource.CONNECTING;
      FakeEventSource.OPEN = NativeEventSource.OPEN;
      FakeEventSource.CLOSED = NativeEventSource.CLOSED;
      window.EventSource = FakeEventSource;
      window.__governorNativeEventSourceForSwitch = NativeEventSource;
      return true;
    })()`);

    await evaluate(tabA, `(() => { document.getElementById('fullScanBtn')?.click(); return true; })()`);
    const sourceDeadline = Date.now() + 10_000;
    let sourceReady = false;
    while (Date.now() < sourceDeadline) {
      sourceReady = await evaluate(tabA, `Boolean(window.__governorFakeScanSource)`).catch(() => false);
      if (sourceReady) break;
      await sleep(50);
    }
    assert(sourceReady, "Fake provider stream was not adopted by the real scan-monitor start path.");

    await evaluate(tabA, `(() => {
      window.__governorFakeScanSource.emit('scan-status', { phase: 'waiting_for_next_batch', message: 'governor marker one' });
      return document.getElementById('scanMonitorStatus')?.textContent || '';
    })()`);
    const firstMarker = await evaluate(tabA, `document.getElementById('scanMonitorStatus')?.textContent || ''`);
    assert(/governor marker one/i.test(firstMarker), `Initial same-account stream update was not visible: ${firstMarker}`);

    await selectAccount(tabA, accountB);
    await selectAccount(tabA, accountA);
    await evaluate(tabA, `(() => {
      window.__governorFakeScanSource.emit('scan-status', { phase: 'waiting_for_next_batch', message: 'governor marker two' });
      return true;
    })()`);
    const secondMarker = await evaluate(tabA, `document.getElementById('scanMonitorStatus')?.textContent || ''`);
    assert(/governor marker two/i.test(secondMarker), `Returning to the running account suppressed later stream updates: ${secondMarker}`);
  });

  await check("Governor browser emitted no uncaught runtime errors", async () => {
    assert(runtimeErrors.length === 0, `Uncaught browser errors: ${JSON.stringify(runtimeErrors)}`);
  });

  if (failures.length) {
    throw new Error(`Governor executable browser failures (${failures.length}):\n- ${failures.join("\n- ")}`);
  }

  console.log(`Executable Governor v2 blocker smoke passed with ${executable}.`);
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
