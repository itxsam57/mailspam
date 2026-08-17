import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { waitForDevToolsPort } from "./chromium-devtools-port.mjs";

const root = process.cwd();
const host = "127.0.0.1";
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-onboarding-smoke-data-"));
const browserProfile = mkdtempSync(join(tmpdir(), "email-shield-onboarding-smoke-profile-"));
let server;
let browser;
let cdpSocket;
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
    if (processRef?.exitCode !== null) {
      throw new Error(`Process exited before ${url} became ready with code ${processRef.exitCode}.\n${stderr()}`);
    }
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
  throw new Error("No Chrome, Chromium, or Edge executable was found for onboarding handoff smoke.");
}

async function connectWebSocket(url, timeoutMs = 10_000) {
  assert(typeof WebSocket === "function", "Node.js WebSocket support is required for onboarding handoff smoke.");
  return await new Promise((resolveSocket, reject) => {
    const socket = new WebSocket(url);
    const timer = setTimeout(() => reject(new Error(`Timed out connecting to DevTools: ${url}`)), timeoutMs);
    socket.addEventListener("open", () => {
      clearTimeout(timer);
      resolveSocket(socket);
    }, { once: true });
    socket.addEventListener("error", () => {
      clearTimeout(timer);
      reject(new Error(`Could not connect to DevTools: ${url}`));
    }, { once: true });
  });
}

function createCdpClient(socket) {
  let nextId = 1;
  const pending = new Map();
  socket.addEventListener("message", (event) => {
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
        socket.send(JSON.stringify({ id, method, params }));
      });
    },
  };
}

async function evaluate(client, expression) {
  const result = await client.send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
  if (result.exceptionDetails) throw new Error(`Browser evaluation failed: ${result.exceptionDetails.text ?? "unknown exception"}`);
  return result.result?.value;
}

try {
  const port = await freePort();
  assert(Number.isInteger(port), "Could not allocate isolated server port.");
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
      EMAIL_SHIELD_ENABLE_DEVELOPMENT_ENTITLEMENTS: "0",
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

  cdpSocket = await connectWebSocket(target.webSocketDebuggerUrl);
  const client = createCdpClient(cdpSocket);
  await Promise.all([client.send("Page.enable"), client.send("Runtime.enable")]);
  const navigation = await client.send("Page.navigate", { url: baseUrl }, 15_000);
  assert(!navigation.errorText, `Browser navigation failed: ${navigation.errorText}`);

  const readyDeadline = Date.now() + 15_000;
  let ready = false;
  while (Date.now() < readyDeadline) {
    try {
      ready = await evaluate(client, `Boolean(
        document.readyState === 'complete'
        && typeof window.emailShieldNavigate === 'function'
        && document.getElementById('consumerFirstRun')
        && document.querySelector('.consumer-provider-grid')
        && document.querySelector('.first-run-step[data-step="sensitivity_chosen"] button')
      )`);
      if (ready) break;
    } catch {}
    await sleep(100);
  }
  assert(ready, "Consumer onboarding/provider surfaces did not become ready in the real browser.");

  const result = await evaluate(client, `(async () => {
    const accountsBefore = document.querySelectorAll('#accountsList .account-chip').length;
    window.emailShieldNavigate('home', { focus: false });
    const sensitivityStep = document.querySelector('.first-run-step[data-step="sensitivity_chosen"]');
    const sensitivityButton = sensitivityStep?.querySelector('button');
    sensitivityButton?.click();
    await new Promise((resolve) => setTimeout(resolve, 100));

    const settings = document.querySelector('.app-route[data-route="settings"]');
    const guidance = document.getElementById('consumerProviderSetupGuidance');
    const grid = document.querySelector('.consumer-provider-grid');
    const focusedProvider = document.activeElement?.dataset?.consumerProvider || null;
    const accountsAfter = document.querySelectorAll('#accountsList .account-chip').length;
    return {
      accountsBefore,
      accountsAfter,
      settingsVisible: settings?.hidden === false,
      guidanceVisible: Boolean(guidance && guidance.hidden === false),
      guidanceTextPresent: Boolean(guidance?.textContent?.includes('Connect a mailbox to continue')),
      providerGridPresent: Boolean(grid),
      providerFocused: typeof focusedProvider === 'string' && focusedProvider.length > 0,
      focusedProvider,
      sensitivityComplete: sensitivityStep?.dataset.complete === 'true',
    };
  })()`);

  assert(result.accountsBefore === 0 && result.accountsAfter === 0, `Onboarding smoke expected zero connected mailboxes: ${JSON.stringify(result)}`);
  assert(result.settingsVisible === true, `Sensitivity prerequisite did not route to Mailboxes & Settings: ${JSON.stringify(result)}`);
  assert(result.guidanceVisible === true && result.guidanceTextPresent === true, `Provider setup guidance did not become visible: ${JSON.stringify(result)}`);
  assert(result.providerGridPresent === true && result.providerFocused === true, `Provider choices were not surfaced/focused: ${JSON.stringify(result)}`);
  assert(result.focusedProvider !== 'outlook', `Postponed Outlook became reachable in normal consumer setup: ${JSON.stringify(result)}`);
  assert(result.sensitivityComplete === false, `Sensitivity was incorrectly credited without a connected mailbox: ${JSON.stringify(result)}`);

  console.log(`Executable onboarding handoff smoke passed with ${browserExecutable}.`);
  console.log("No-mailbox sensitivity action routed to provider setup, surfaced guidance/provider focus, preserved Outlook postponement, and granted no false completion.");
} finally {
  try { cdpSocket?.close(); } catch {}
  if (browser && browser.exitCode === null) {
    try { browser.kill(); } catch {}
  }
  if (server && server.exitCode === null) {
    try { server.kill(); } catch {}
  }
  await sleep(150);
  try { rmSync(browserProfile, { recursive: true, force: true }); } catch {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch {}
}
