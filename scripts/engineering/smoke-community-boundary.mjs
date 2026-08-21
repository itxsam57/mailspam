import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { waitForDevToolsPort } from "./chromium-devtools-port.mjs";

const root = process.cwd();
const host = "127.0.0.1";
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-community-boundary-data-"));
const browserProfile = mkdtempSync(join(tmpdir(), "email-shield-community-boundary-browser-"));
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
  throw new Error("No Chrome, Chromium, or Edge executable was found for Community boundary smoke.");
}

async function connectWebSocket(url, timeoutMs = 10_000) {
  assert(typeof WebSocket === "function", "Node.js WebSocket support is required for Community boundary smoke.");
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
  const listeners = new Map();

  socket.addEventListener("message", (event) => {
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
    const bucket = listeners.get(message.method);
    if (!bucket) return;
    for (const listener of bucket) listener(message.params ?? {});
  });

  return {
    on(method, listener) {
      const bucket = listeners.get(method) ?? new Set();
      bucket.add(listener);
      listeners.set(method, bucket);
      return () => bucket.delete(listener);
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

async function navigateAndWait(client, url, readyExpression, timeoutMs = 15_000) {
  const navigation = await client.send("Page.navigate", { url }, timeoutMs);
  assert(!navigation.errorText, `Browser navigation failed: ${navigation.errorText}`);
  const deadline = Date.now() + timeoutMs;
  let lastSnapshot = null;
  while (Date.now() < deadline) {
    try {
      lastSnapshot = await evaluate(client, readyExpression);
      if (lastSnapshot?.ready === true) return lastSnapshot;
    } catch {}
    await sleep(100);
  }
  throw new Error(`Timed out waiting for Community boundary browser state at ${url}: ${JSON.stringify(lastSnapshot)}`);
}

try {
  const port = await freePort();
  assert(Number.isInteger(port), "Could not allocate isolated Community boundary port.");
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

  cdpSocket = await connectWebSocket(target.webSocketDebuggerUrl);
  const client = createCdpClient(cdpSocket);
  const runtimeExceptions = [];
  client.on("Runtime.exceptionThrown", ({ exceptionDetails }) => {
    runtimeExceptions.push(exceptionDetails?.exception?.description || exceptionDetails?.text || "browser exception");
  });
  await Promise.all([client.send("Page.enable"), client.send("Runtime.enable")]);

  const retired = await navigateAndWait(client, `${baseUrl}/#community`, `(() => {
    const home = document.querySelector('.app-route[data-route="home"]');
    const operations = document.getElementById('operationsPanel');
    const routerReady = typeof window.emailShieldNavigate === 'function';
    return {
      ready: document.readyState === 'complete' && routerReady && Boolean(home) && Boolean(operations),
      hash: location.hash,
      communityNav: Boolean(document.querySelector('[data-route-target="community"], [data-mobile-route="community"]')),
      communityRoute: Boolean(document.querySelector('.app-route[data-route="community"]')),
      homeVisible: home?.hidden === false,
      operationsHidden: operations?.hidden === true,
      operationsEnabled: operations?.dataset?.emailShieldDeveloperEnabled || null,
    };
  })()`);

  assert(retired.hash === '#home', `Direct #community did not migrate to #home: ${JSON.stringify(retired)}`);
  assert(retired.communityNav === false && retired.communityRoute === false, `Consumer still exposes retired Community UI: ${JSON.stringify(retired)}`);
  assert(retired.homeVisible === true, `Home is not visible after retired Community migration: ${JSON.stringify(retired)}`);
  assert(retired.operationsHidden === true && retired.operationsEnabled !== 'true', `Consumer operations diagnostics became visible without explicit developer UI request: ${JSON.stringify(retired)}`);

  const developer = await navigateAndWait(client, `${baseUrl}/?developer=1#settings`, `(() => {
    const settings = document.querySelector('.app-route[data-route="settings"]');
    const operations = document.getElementById('operationsPanel');
    const status = document.getElementById('operationsStatus');
    const summary = document.getElementById('operationsSummary');
    const statusText = status?.textContent?.trim() || '';
    const summaryText = summary?.textContent?.trim() || '';
    return {
      ready: document.readyState === 'complete'
        && typeof window.emailShieldNavigate === 'function'
        && settings?.hidden === false
        && operations?.hidden === false
        && operations?.dataset?.emailShieldDeveloperEnabled === 'true'
        && statusText.includes('Aggregate operations refreshed')
        && summaryText.includes('Feed:'),
      hash: location.hash,
      communityNav: Boolean(document.querySelector('[data-route-target="community"], [data-mobile-route="community"]')),
      communityRoute: Boolean(document.querySelector('.app-route[data-route="community"]')),
      settingsVisible: settings?.hidden === false,
      operationsHidden: operations?.hidden === true,
      operationsEnabled: operations?.dataset?.emailShieldDeveloperEnabled || null,
      statusText,
      summaryText,
    };
  })()`);

  assert(developer.hash === '#settings', `Developer diagnostics did not remain on Settings: ${JSON.stringify(developer)}`);
  assert(developer.communityNav === false && developer.communityRoute === false, `Developer mode revived retired Community UI: ${JSON.stringify(developer)}`);
  assert(developer.settingsVisible === true, `Developer Settings route is not visible: ${JSON.stringify(developer)}`);
  assert(developer.operationsHidden === false && developer.operationsEnabled === 'true', `Entitled operations diagnostics did not become visible: ${JSON.stringify(developer)}`);
  assert(developer.statusText.includes('Aggregate operations refreshed') && developer.summaryText.includes('Feed:'), `Entitled aggregate diagnostics did not render: ${JSON.stringify(developer)}`);
  assert(runtimeExceptions.length === 0, `Community boundary smoke observed browser runtime errors: ${runtimeExceptions.join(" | ")}`);

  console.log(`Executable Community/operations boundary smoke passed with ${browserExecutable}.`);
  console.log("Direct #community retired to Home with no Community navigation/route DOM and no consumer diagnostics exposure.");
  console.log("Explicit ?developer=1 plus development entitlement rendered aggregate-only operations diagnostics under Settings.");
} catch (error) {
  console.error(`FAIL: ${error instanceof Error ? error.message : String(error)}`);
  if (serverStderr.trim()) console.error(`Server stderr:\n${serverStderr.trim()}`);
  if (browserStderr.trim()) console.error(`Browser stderr:\n${browserStderr.trim()}`);
  process.exitCode = 1;
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
