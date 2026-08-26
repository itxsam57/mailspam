import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { waitForDevToolsPort } from "./chromium-devtools-port.mjs";

const root = process.cwd();
const host = "127.0.0.1";
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-trash-data-"));
const browserProfile = mkdtempSync(join(tmpdir(), "email-shield-trash-profile-"));
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
  if (!childProcessExited(processRef)) throw new Error(`${label} did not exit during Trash-action teardown.`);
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
    if (childProcessExited(processRef)) throw new Error(`Process exited before ${url} became ready.\n${stderr()}`);
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(2_000) });
      if (response.ok) return;
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
  throw new Error("No Chrome, Chromium, or Edge executable was found for the Trash-action gate.");
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

async function waitForScanComplete(client, timeoutMs = 45_000) {
  const deadline = Date.now() + timeoutMs;
  let state = null;
  while (Date.now() < deadline) {
    state = await evaluate(client, `(() => ({
      status: document.getElementById('scanMonitorStatus')?.textContent || '',
      busy: document.getElementById('scanPanel')?.getAttribute('aria-busy') || '',
      trashButtons: [...document.querySelectorAll('.card button[data-action="trash"]')]
        .filter((button) => !button.disabled && button.dataset.reviewToken).length,
      cards: document.querySelectorAll('#cards .card').length,
    }))()`);
    // Trash behavior is the subject of this smoke. Completion is established by
    // the canonical scan owner releasing aria-busy and exposing an authorized
    // Trash capability; do not couple this gate to presentation wording that can
    // legitimately say either "Scan complete" or "Reattached scan complete".
    if (state?.busy !== "true" && state?.trashButtons > 0) return state;
    await sleep(100);
  }
  throw new Error(`Full scan did not complete before the Trash-action deadline. Last state: ${JSON.stringify(state)}`);
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
  const navigation = await client.send("Page.navigate", { url: `${baseUrl}/?developer=1` }, 15_000);
  assert(!navigation.errorText, `Browser navigation failed: ${navigation.errorText}`);

  const readyDeadline = Date.now() + 15_000;
  let ready = false;
  while (Date.now() < readyDeadline) {
    ready = await evaluate(client, `Boolean(
      document.readyState === 'complete' &&
      window.emailShieldSecureFetchInstalled === true &&
      typeof window.emailShieldSelectAccount === 'function' &&
      typeof window.emailShieldNavigate === 'function' &&
      typeof window.emailShieldStartScan === 'function' &&
      document.getElementById('fullScanBtn')
    )`).catch(() => false);
    if (ready) break;
    await sleep(100);
  }
  assert(ready, "Trash-action browser gate could not reach the initialized consumer dashboard.");

  const accountId = await evaluate(client, `(async () => {
    const response = await fetch('/api/accounts/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'gmail', mode: 'fixture', label: 'trash-action-fixture' }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || typeof body.accountId !== 'string') throw new Error(body.error || 'Fixture connection failed.');
    await refreshAccounts();
    window.emailShieldSelectAccount(body.accountId, { remember: false });
    window.emailShieldNavigate('scan', { focus: false });
    document.getElementById('fullScanBtn').click();
    return body.accountId;
  })()`, 20_000);
  assert(typeof accountId === "string" && accountId.length > 0, "Trash-action fixture account did not return an account id.");

  const firstScan = await waitForScanComplete(client);
  assert(firstScan.trashButtons > 0, `Full fixture scan exposed no standalone Trash action. State: ${JSON.stringify(firstScan)}`);

  const targetState = await evaluate(client, `(() => {
    const button = [...document.querySelectorAll('.card button[data-action="trash"]')]
      .find((candidate) => !candidate.disabled && candidate.dataset.reviewToken) || null;
    const card = button?.closest('.card') || null;
    const subject = card?.querySelector('.card-subject')?.textContent?.trim() || '';
    const sender = card?.querySelector('.card-from')?.textContent?.trim() || '';
    const matchingBefore = [...document.querySelectorAll('#cards .card')].filter((candidate) =>
      candidate.querySelector('.card-subject')?.textContent?.trim() === subject &&
      candidate.querySelector('.card-from')?.textContent?.trim() === sender
    ).length;
    return {
      token: button?.dataset.reviewToken || '',
      subject,
      sender,
      matchingBefore,
    };
  })()`);
  assert(targetState?.token && targetState?.subject && targetState.matchingBefore > 0,
    `Trash-action target could not be identified. State: ${JSON.stringify(targetState)}`);

  await evaluate(client, `(() => {
    window.confirm = () => true;
    window.__ema39TrashTrace = [];
    const originalFetch = window.fetch.bind(window);
    window.fetch = async (...args) => {
      const url = typeof args[0] === 'string' ? args[0] : args[0]?.url || '';
      const response = await originalFetch(...args);
      if (url.includes('/messages/trash')) {
        let body = null;
        try { body = await response.clone().json(); } catch {}
        window.__ema39TrashTrace.push({ url, status: response.status, ok: response.ok, body });
      }
      return response;
    };
    const button = document.querySelector('[data-action="trash"][data-review-token="${targetState.token}"]');
    if (!(button instanceof HTMLButtonElement)) throw new Error('Target Trash button disappeared before click.');
    button.click();
    return true;
  })()`);

  const actionDeadline = Date.now() + 15_000;
  let actionState = null;
  while (Date.now() < actionDeadline) {
    actionState = await evaluate(client, `(() => {
      const button = document.querySelector('[data-action="trash"][data-review-token="${targetState.token}"]');
      const card = button?.closest('.card') || null;
      return {
        buttonDisabled: button?.disabled === true,
        buttonText: button?.textContent || '',
        cardMoved: card?.classList.contains('trash-moved') === true,
        actionStatus: card?.querySelector('.trash-action-status')?.textContent || '',
        globalStatus: document.getElementById('scanMonitorStatus')?.textContent || '',
        trace: window.__ema39TrashTrace || [],
      };
    })()`);
    if (actionState?.buttonDisabled && actionState?.cardMoved && actionState?.trace?.length === 1) break;
    await sleep(100);
  }

  assert(actionState?.trace?.length === 1, `Standalone Trash did not make exactly one protected mutation request. State: ${JSON.stringify(actionState)}`);
  const receipt = actionState.trace[0];
  assert(receipt.status === 200 && receipt.ok === true, `Trash API did not return HTTP success. Receipt: ${JSON.stringify(receipt)}`);
  assert(receipt.body?.requested === 1 && receipt.body?.moved === 1 && receipt.body?.success === true,
    `Trash API did not confirm exact request/move cardinality. Receipt: ${JSON.stringify(receipt)}`);
  assert(Array.isArray(receipt.body?.failed) && receipt.body.failed.length === 0,
    `Trash API reported a provider failure despite UI success. Receipt: ${JSON.stringify(receipt)}`);
  assert(receipt.body?.accountId === accountId && receipt.body?.token === targetState.token,
    `Trash API confirmation did not belong to the selected account/action token. Receipt: ${JSON.stringify(receipt)}`);
  assert(actionState.buttonDisabled === true && actionState.buttonText.includes('Moved to Trash'),
    `Trash button did not settle to visible success. State: ${JSON.stringify(actionState)}`);
  assert(actionState.cardMoved === true && actionState.actionStatus.includes('exactly one message was moved to Trash'),
    `Trash card did not expose the provider-confirmed success consequence. State: ${JSON.stringify(actionState)}`);
  assert(actionState.globalStatus.includes('Exactly one message was moved to the provider Trash folder'),
    `Global scan status did not truthfully announce standalone Trash success. State: ${JSON.stringify(actionState)}`);

  await evaluate(client, `document.getElementById('fullScanBtn').click()`);
  await waitForScanComplete(client);
  const rescanState = await evaluate(client, `(() => {
    const matchingAfter = [...document.querySelectorAll('#cards .card')].filter((candidate) =>
      candidate.querySelector('.card-subject')?.textContent?.trim() === ${JSON.stringify(targetState.subject)} &&
      candidate.querySelector('.card-from')?.textContent?.trim() === ${JSON.stringify(targetState.sender)}
    ).length;
    return {
      matchingAfter,
      status: document.getElementById('scanMonitorStatus')?.textContent || '',
    };
  })()`);
  assert(rescanState.matchingAfter === targetState.matchingBefore - 1,
    `Provider-backed fixture rescan did not remove exactly the moved message. Before=${targetState.matchingBefore} after=${rescanState.matchingAfter} target=${targetState.subject} / ${targetState.sender}`);
  assert(runtimeErrors.length === 0, `Trash-action browser flow produced uncaught errors: ${JSON.stringify(runtimeErrors)}`);

  console.log(`Executable standalone Trash smoke passed with ${executable}.`);
  console.log(`Provider confirmed requested=1 moved=1 for ${targetState.subject}.`);
  console.log(`Rescan matching count decreased ${targetState.matchingBefore} -> ${rescanState.matchingAfter}.`);
} catch (error) {
  console.error(`FAIL: ${error.message}`);
  if (serverStderr.trim()) console.error(`Server stderr:\n${serverStderr.trim()}`);
  if (browserStderr.trim()) console.error(`Browser stderr:\n${browserStderr.trim()}`);
  process.exitCode = 1;
} finally {
  try { socket?.close(); } catch {}
  try { await stopChildProcess(browser, "Chromium"); } catch (error) { console.error(error.message); process.exitCode = 1; }
  try { await stopChildProcess(server, "Email Shield server"); } catch (error) { console.error(error.message); process.exitCode = 1; }
  try { rmSync(browserProfile, { recursive: true, force: true }); } catch {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch {}
}