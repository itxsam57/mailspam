import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { waitForDevToolsPort } from "./chromium-devtools-port.mjs";

const root = process.cwd();
const host = "127.0.0.1";
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-restore-smoke-data-"));
const browserProfile = mkdtempSync(join(tmpdir(), "email-shield-restore-smoke-browser-"));
let server;
let browser;
let socket;
let serverStderr = "";
let browserStderr = "";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function sleep(ms) {
  return new Promise((resolveWait) => setTimeout(resolveWait, ms));
}

async function freePort() {
  return await new Promise((resolvePort, reject) => {
    const listener = net.createServer();
    listener.on("error", reject);
    listener.listen(0, host, () => {
      const address = listener.address();
      const port = typeof address === "object" && address ? address.port : null;
      listener.close((error) => error ? reject(error) : resolvePort(port));
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
      if (response.ok) return response;
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await sleep(100);
  }
  throw new Error(`Timed out waiting for ${url}: ${lastError?.message ?? "unknown error"}\n${stderr()}`);
}

function findOnPath(command) {
  const lookup = process.platform === "win32" ? "where" : "which";
  const result = spawnSync(lookup, [command], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
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
      candidates.push(
        join(base, "Google", "Chrome", "Application", "chrome.exe"),
        join(base, "Microsoft", "Edge", "Application", "msedge.exe"),
      );
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
    const located = findOnPath(command);
    if (located) return located;
  }
  throw new Error("No Chrome, Chromium, or Edge executable was found for Restore Purchase smoke.");
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

function createClient(cdpSocket) {
  let nextId = 1;
  const pending = new Map();
  const browserErrors = [];
  cdpSocket.addEventListener("message", (event) => {
    let message;
    try { message = JSON.parse(String(event.data)); } catch { return; }
    if (message.method === "Runtime.exceptionThrown") {
      browserErrors.push(message.params?.exceptionDetails?.text ?? "Uncaught browser exception");
    }
    if (typeof message.id !== "number") return;
    const waiter = pending.get(message.id);
    if (!waiter) return;
    pending.delete(message.id);
    if (message.error) waiter.reject(new Error(`${waiter.method}: ${message.error.message ?? "DevTools error"}`));
    else waiter.resolve(message.result ?? {});
  });
  return {
    browserErrors,
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
        cdpSocket.send(JSON.stringify({ id, method, params }));
      });
    },
  };
}

async function evaluate(client, expression) {
  const result = await client.send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
  if (result.exceptionDetails) throw new Error(`Browser evaluation failed: ${result.exceptionDetails.text ?? "unknown exception"}`);
  return result.result?.value;
}

async function waitUntil(client, expression, message, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if (await evaluate(client, expression)) return;
    } catch {}
    await sleep(100);
  }
  throw new Error(message);
}

try {
  const port = await freePort();
  assert(Number.isInteger(port), "Could not allocate isolated Restore Purchase server port.");
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

  const browserExecutable = findBrowser();
  browser = spawn(browserExecutable, [
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
  const target = Array.isArray(targets) ? targets.find((candidate) => candidate.type === "page" && candidate.webSocketDebuggerUrl) : null;
  assert(target?.webSocketDebuggerUrl, `Browser DevTools exposed no page target.\n${browserStderr}`);

  socket = await connectWebSocket(target.webSocketDebuggerUrl);
  const client = createClient(socket);
  await Promise.all([client.send("Page.enable"), client.send("Runtime.enable")]);
  const navigation = await client.send("Page.navigate", { url: baseUrl }, 15_000);
  assert(!navigation.errorText, `Browser navigation failed: ${navigation.errorText}`);

  await waitUntil(
    client,
    `Boolean(document.readyState === 'complete' && typeof window.emailShieldNavigate === 'function' && document.getElementById('accountCreate'))`,
    "Account UI did not become ready for Restore Purchase acceptance.",
  );

  const settingsOwnership = await evaluate(client, `(() => {
    window.emailShieldNavigate('settings', { focus: false });
    const protection = document.getElementById('backgroundProtection');
    const route = protection?.closest('.app-route');
    const heading = protection?.querySelector('h3')?.textContent?.trim() || '';
    return {
      route: route?.dataset.route || null,
      routeVisible: route?.hidden === false,
      heading,
      togglePresent: Boolean(protection?.querySelector('#backgroundToggle')),
    };
  })()`);
  assert(settingsOwnership.route === 'settings' && settingsOwnership.routeVisible === true, `Continuous Protection was not visibly owned by Mailboxes & Settings: ${JSON.stringify(settingsOwnership)}`);
  assert(settingsOwnership.heading === 'Continuous Protection' && settingsOwnership.togglePresent === true, `Continuous Protection control was not consumer-visible under Settings: ${JSON.stringify(settingsOwnership)}`);

  const createStarted = await evaluate(client, `(() => {
    window.emailShieldNavigate('account', { focus: false });
    const username = document.getElementById('accountCreateUsername');
    const label = document.getElementById('accountDeviceLabel');
    const create = document.getElementById('accountCreate');
    if (!(username instanceof HTMLInputElement) || !(label instanceof HTMLInputElement) || !(create instanceof HTMLButtonElement)) return false;
    username.value = 'restore-smoke';
    label.value = 'Restore acceptance';
    create.click();
    return true;
  })()`);
  assert(createStarted === true, "Could not create the isolated Email Shield profile through the real Account UI.");

  await waitUntil(
    client,
    `Boolean(document.getElementById('accountSignedIn')?.hidden === false && document.getElementById('consumerRestorePurchase'))`,
    `Signed-in billing UI did not mount. Server stderr:\n${serverStderr}`,
    20_000,
  );

  const bridgeUnavailable = await evaluate(client, `(async () => {
    const button = document.getElementById('consumerRestorePurchase');
    const status = document.getElementById('consumerBillingStatus');
    button?.click();
    await new Promise((resolve) => setTimeout(resolve, 25));
    return { state: status?.dataset.restoreState || null, text: status?.textContent || '' };
  })()`);
  assert(bridgeUnavailable.state === 'bridge_unavailable', `Restore did not terminate fail-closed when no signed store bridge existed: ${JSON.stringify(bridgeUnavailable)}`);

  const nothingToRestore = await evaluate(client, `(async () => {
    window.emailShieldBillingBridge = { restore: async () => ({ code: 'nothing_to_restore' }) };
    const button = document.getElementById('consumerRestorePurchase');
    const status = document.getElementById('consumerBillingStatus');
    button?.click();
    for (let attempt = 0; attempt < 40 && status?.dataset.restoreState !== 'nothing_to_restore'; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    return { state: status?.dataset.restoreState || null, text: status?.textContent || '' };
  })()`);
  assert(nothingToRestore.state === 'nothing_to_restore', `Restore did not reach the no-purchase terminal state: ${JSON.stringify(nothingToRestore)}`);
  assert(/No restorable Email Shield purchase/i.test(nothingToRestore.text), `No-purchase result was not consumer-readable: ${JSON.stringify(nothingToRestore)}`);

  const rejected = await evaluate(client, `(async () => {
    window.emailShieldBillingBridge = { restore: async () => ({ verified: false, receipt: 'RAW_STORE_EVIDENCE_MUST_NOT_RENDER' }) };
    const button = document.getElementById('consumerRestorePurchase');
    const status = document.getElementById('consumerBillingStatus');
    button?.click();
    for (let attempt = 0; attempt < 40 && status?.dataset.restoreState !== 'verification_rejected'; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    return { state: status?.dataset.restoreState || null, text: status?.textContent || '' };
  })()`);
  assert(rejected.state === 'verification_rejected', `Unverified store evidence did not fail closed: ${JSON.stringify(rejected)}`);
  assert(!rejected.text.includes('RAW_STORE_EVIDENCE_MUST_NOT_RENDER'), `Restore leaked raw store evidence into the UI: ${JSON.stringify(rejected)}`);
  assert(/No paid access was granted/i.test(rejected.text), `Verification rejection did not explain the safe outcome: ${JSON.stringify(rejected)}`);

  const staleSafe = await evaluate(client, `(async () => {
    let calls = 0;
    window.emailShieldBillingBridge = {
      restore: async () => {
        calls += 1;
        if (calls === 1) {
          await new Promise((resolve) => setTimeout(resolve, 180));
          return { verified: true };
        }
        return { code: 'nothing_to_restore' };
      },
    };
    const button = document.getElementById('consumerRestorePurchase');
    const status = document.getElementById('consumerBillingStatus');
    button?.click();
    await new Promise((resolve) => setTimeout(resolve, 20));
    button?.click();
    await new Promise((resolve) => setTimeout(resolve, 260));
    return { state: status?.dataset.restoreState || null, text: status?.textContent || '', calls };
  })()`);
  assert(staleSafe.calls === 2 && staleSafe.state === 'nothing_to_restore', `An older Restore response overwrote the newer terminal result: ${JSON.stringify(staleSafe)}`);

  assert(client.browserErrors.length === 0, `Uncaught browser errors occurred during Restore Purchase acceptance: ${client.browserErrors.join(' | ')}`);
  console.log(`Executable Restore Purchase smoke passed with ${browserExecutable}.`);
  console.log('Continuous Protection was visibly owned by Settings; real Account UI reached bridge-unavailable, nothing-to-restore, verification-rejected, and stale-safe Restore terminal states without exposing raw store evidence.');
} finally {
  try { socket?.close(); } catch {}
  if (browser && browser.exitCode === null) {
    try { browser.kill(); } catch {}
  }
  if (server && server.exitCode === null) {
    try { server.kill(); } catch {}
  }
  await sleep(200);
  try { rmSync(browserProfile, { recursive: true, force: true, maxRetries: 4, retryDelay: 100 }); } catch {}
  try { rmSync(dataDir, { recursive: true, force: true, maxRetries: 4, retryDelay: 100 }); } catch {}
}