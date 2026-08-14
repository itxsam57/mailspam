import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = process.cwd();
const host = "127.0.0.1";
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-release-browser-data-"));
const browserProfile = mkdtempSync(join(tmpdir(), "email-shield-release-browser-profile-"));
let server;
let browser;
let socket;
let serverStderr = "";
let browserStderr = "";
const runtimeErrors = [];

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
      if (response.ok) return;
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
  throw new Error("No Chrome, Chromium, or Edge executable was found for the release browser gate. Set EMAIL_SHIELD_TEST_BROWSER to an installed Chromium-family browser.");
}

function createCdpClient(webSocket) {
  let nextId = 1;
  const pending = new Map();
  const listeners = new Map();
  webSocket.addEventListener("message", (event) => {
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
        webSocket.send(JSON.stringify({ id, method, params }));
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
  if (result.exceptionDetails) throw new Error(`Browser evaluation failed: ${result.exceptionDetails.text ?? "unknown exception"}`);
  return result.result?.value;
}

try {
  const port = await freePort();
  const debugPort = await freePort();
  assert(Number.isInteger(port) && Number.isInteger(debugPort), "Could not allocate isolated release browser ports.");
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
      EMAIL_SHIELD_GOOGLE_CLIENT_ID: "",
      EMAIL_SHIELD_MICROSOFT_CLIENT_ID: "",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  server.stderr.setEncoding("utf8");
  server.stderr.on("data", (chunk) => { serverStderr += chunk; });
  await waitForHttp(baseUrl, server, () => serverStderr);

  const browserExecutable = findBrowser();
  browser = spawn(browserExecutable, [
    "--headless=new",
    `--remote-debugging-port=${debugPort}`,
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

  await waitForHttp(`http://${host}:${debugPort}/json/version`, browser, () => browserStderr, 15_000);
  const targets = await (await fetch(`http://${host}:${debugPort}/json/list`, { signal: AbortSignal.timeout(5_000) })).json();
  const target = Array.isArray(targets) ? targets.find((candidate) => candidate.type === "page" && candidate.webSocketDebuggerUrl) : null;
  assert(target?.webSocketDebuggerUrl, `Browser DevTools exposed no page target.\n${browserStderr}`);

  socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolveOpen, reject) => {
    const timer = setTimeout(() => reject(new Error("Timed out connecting to browser DevTools.")), 10_000);
    socket.addEventListener("open", () => { clearTimeout(timer); resolveOpen(); }, { once: true });
    socket.addEventListener("error", () => { clearTimeout(timer); reject(new Error("Could not connect to browser DevTools.")); }, { once: true });
  });
  const client = createCdpClient(socket);
  client.on("Runtime.exceptionThrown", (params) => runtimeErrors.push(params.exceptionDetails?.text ?? "runtime exception"));
  await client.send("Runtime.enable");
  await client.send("Page.enable");
  await client.send("Emulation.setDeviceMetricsOverride", {
    width: 390,
    height: 844,
    deviceScaleFactor: 1,
    mobile: true,
  });
  await client.send("Page.navigate", { url: `${baseUrl}/?developer=1` });

  const deadline = Date.now() + 20_000;
  let ready = false;
  while (Date.now() < deadline) {
    ready = await evaluate(client, `Boolean(document.readyState === 'complete' && window.emailShieldSecureFetchInstalled && window.emailShieldNavigate && document.querySelector('.app-sidebar'))`).catch(() => false);
    if (ready) break;
    await sleep(100);
  }
  assert(ready, "Release consumer browser gate could not reach the initialized dashboard.");

  const surface = await evaluate(client, `(() => {
    const legacyHeader = document.querySelector('body.email-shield-shell > header');
    const devButton = document.getElementById('devSuiteBtn');
    const fixtureButton = [...document.querySelectorAll('button')].find((button) => button.textContent?.trim() === 'Use fixture mode') || null;
    const high = document.querySelector('[data-consumer-sensitivity]');
    return {
      developerQueryRemoved: !new URLSearchParams(location.search).has('developer'),
      developmentAuthorized: window.emailShieldDevelopmentEntitlementsEnabled === true,
      legacyHeaderDisplay: legacyHeader ? getComputedStyle(legacyHeader).display : 'missing',
      devButtonDisplay: devButton ? getComputedStyle(devButton).display : 'missing',
      fixtureControlVisible: Boolean(fixtureButton && getComputedStyle(fixtureButton).display !== 'none'),
      developerDetailsPresent: document.body.innerText.includes('Developer acceptance controls'),
      highProfile: high?.dataset.consumerSensitivity || null,
      width: innerWidth,
    };
  })()`);

  assert(surface.developerQueryRemoved === true, `Release browser retained developer query authority: ${JSON.stringify(surface)}`);
  assert(surface.developmentAuthorized === false, `Release browser exposed development authorization: ${JSON.stringify(surface)}`);
  assert(surface.legacyHeaderDisplay === "none", `Legacy developer/header surface reappeared at mobile width: ${JSON.stringify(surface)}`);
  assert(surface.fixtureControlVisible === false && surface.developerDetailsPresent === false, `Fixture/developer controls were visible in release mode: ${JSON.stringify(surface)}`);
  assert(surface.highProfile === "high", `High Protection browser control is not canonical: ${JSON.stringify(surface)}`);
  assert(surface.width <= 390, `Release smoke did not exercise a narrow/mobile viewport: ${JSON.stringify(surface)}`);

  const serverBoundary = await evaluate(client, `(async () => {
    const dev = await fetch('/api/dev/test-suite');
    const fixture = await fetch('/api/accounts/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'gmail', mode: 'fixture', label: 'release-browser-must-reject' }),
    });
    return {
      devStatus: dev.status,
      fixtureStatus: fixture.status,
      fixtureBody: await fixture.json().catch(() => ({})),
    };
  })()`, 15_000);
  assert(serverBoundary.devStatus === 404, `Release browser reached developer suite API: ${JSON.stringify(serverBoundary)}`);
  assert(serverBoundary.fixtureStatus === 404, `Release browser connected a fixture mailbox: ${JSON.stringify(serverBoundary)}`);

  const oauth = await evaluate(client, `(async () => {
    const buttons = [...document.querySelectorAll('.consumer-provider')];
    const google = buttons.find((button) => button.textContent?.includes('Continue with Google'));
    const microsoft = buttons.find((button) => button.textContent?.includes('Continue with Microsoft'));
    if (!google || !microsoft) throw new Error('Consumer provider buttons are missing.');
    google.click();
    await new Promise((resolve) => setTimeout(resolve, 250));
    const googleText = document.getElementById('gmailOAuthStatus')?.textContent || '';
    microsoft.click();
    await new Promise((resolve) => setTimeout(resolve, 250));
    const microsoftText = document.getElementById('outlookOAuthStatus')?.textContent || '';
    return { googleText, microsoftText };
  })()`, 10_000);
  for (const [provider, text] of Object.entries(oauth)) {
    assert(/unavailable/i.test(text), `${provider} unavailable state was not consumer-readable: ${JSON.stringify(oauth)}`);
    assert(!/client[ -]?id|configure|development build/i.test(text), `${provider} exposed developer OAuth setup instructions: ${JSON.stringify(oauth)}`);
  }

  assert(runtimeErrors.length === 0, `Release consumer browser produced runtime exceptions: ${JSON.stringify(runtimeErrors)}`);
  console.log(`Executable release-mode consumer smoke passed with ${browserExecutable}.`);
  console.log("Mobile/narrow UI kept developer surfaces hidden and canonical High Protection wiring intact.");
  console.log("Release server rejected developer-suite and fixture-mailbox requests.");
  console.log("Unconfigured Google/Microsoft states remained consumer-safe.");
} catch (error) {
  console.error(`FAIL: ${error.message}`);
  if (serverStderr.trim()) console.error(`Server stderr:\n${serverStderr.trim()}`);
  if (browserStderr.trim()) console.error(`Browser stderr:\n${browserStderr.trim()}`);
  process.exitCode = 1;
} finally {
  try { socket?.close(); } catch {}
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
