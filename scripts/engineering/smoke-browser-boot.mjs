import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = process.cwd();
const host = "127.0.0.1";
const webDir = resolve(root, "web");
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-browser-smoke-data-"));
const browserProfile = mkdtempSync(join(tmpdir(), "email-shield-browser-smoke-profile-"));
const smokeHtmlPath = join(webDir, "__email-shield-browser-smoke.html");
const monitorPath = join(webDir, "__email-shield-browser-smoke-monitor.js");
const checkpointPath = join(webDir, "__email-shield-browser-smoke-checkpoint.js");
const probePath = join(webDir, "__email-shield-browser-smoke-probe.js");
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
  throw new Error("No Chrome, Chromium, or Edge executable was found for the browser boot gate. Set EMAIL_SHIELD_TEST_BROWSER to an installed Chromium-family browser.");
}

function buildProbePage(dashboardHtml, cookie) {
  const cookieScript = `<script>document.cookie=${JSON.stringify(`${cookie}; Path=/; SameSite=Strict`)};</script>`;
  const monitorScript = '<script src="/__email-shield-browser-smoke-monitor.js"></script>';
  const probeScript = '<script defer src="/__email-shield-browser-smoke-probe.js"></script>';
  const withMonitor = dashboardHtml.replace("<head>", `<head>${cookieScript}${monitorScript}`);
  assert(withMonitor !== dashboardHtml, "Browser smoke could not install its same-origin session/error monitor before dashboard code.");

  let productionScriptCount = 0;
  const withCheckpoints = withMonitor.replace(/<script defer src="([^"]+\.js)"><\/script>/g, (tag, src) => {
    productionScriptCount += 1;
    return `${tag}<script defer src="/__email-shield-browser-smoke-checkpoint.js?after=${encodeURIComponent(src)}"></script>`;
  });
  assert(productionScriptCount >= 20, `Browser smoke expected the complete production dashboard script chain but found only ${productionScriptCount} deferred JavaScript files.`);

  const withProbe = withCheckpoints.replace("</body>", `${probeScript}</body>`);
  assert(withProbe !== withCheckpoints, "Browser smoke could not append its final deferred boot probe.");
  return withProbe;
}

async function connectWebSocket(url, timeoutMs = 10_000) {
  assert(typeof WebSocket === "function", "Node.js WebSocket support is required for the browser boot gate.");
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
    try { message = JSON.parse(String(event.data)); }
    catch { return; }

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

try {
  const port = await freePort();
  const debugPort = await freePort();
  assert(Number.isInteger(port) && Number.isInteger(debugPort), "Could not allocate isolated server/browser ports.");
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

  const dashboardResponse = await fetch(baseUrl, { signal: AbortSignal.timeout(5_000) });
  const dashboardHtml = await dashboardResponse.text();
  const cookie = dashboardResponse.headers.get("set-cookie")?.split(";", 1)[0] ?? "";
  assert(dashboardResponse.ok, `Dashboard returned HTTP ${dashboardResponse.status} while preparing browser smoke.`);
  assert(cookie.startsWith("email_shield_local_session="), "Browser smoke could not obtain the protected local dashboard session.");

  writeFileSync(monitorPath, `window.__emailShieldBrowserSmokeErrors=[];\nwindow.addEventListener('error',(event)=>window.__emailShieldBrowserSmokeErrors.push(String(event.error?.stack||event.message||'browser error')));\nwindow.addEventListener('unhandledrejection',(event)=>window.__emailShieldBrowserSmokeErrors.push(String(event.reason?.stack||event.reason||'unhandled rejection')));\n`);
  writeFileSync(checkpointPath, `(() => {\n  const after = new URL(document.currentScript.src).searchParams.get('after') || 'unknown';\n  console.log('__EMAIL_SHIELD_BOOT_CHECKPOINT__', after);\n})();\n`);
  writeFileSync(probePath, `(() => {\n  const errors = Array.isArray(window.__emailShieldBrowserSmokeErrors) ? window.__emailShieldBrowserSmokeErrors : ['error monitor missing'];\n  let singleOwner = false; let scanOk = false; let scanVisible = false; let homeOk = false; let homeVisible = false;\n  try {\n    singleOwner = typeof window.emailShieldNavigate === 'function' && window.emailShieldRouter && window.emailShieldNavigate === window.emailShieldRouter.navigate;\n    scanOk = window.emailShieldNavigate?.('scan', { focus: false }) === true;\n    scanVisible = document.querySelector('.app-route[data-route="scan"]')?.hidden === false;\n    homeOk = window.emailShieldNavigate?.('home', { focus: false }) === true;\n    homeVisible = document.querySelector('.app-route[data-route="home"]')?.hidden === false;\n  } catch (error) { errors.push(String(error?.stack || error)); }\n  window.__emailShieldBrowserSmokeResult = { pass: errors.length === 0 && singleOwner && scanOk && scanVisible && homeOk && homeVisible, errors, singleOwner: Boolean(singleOwner), routing: Boolean(scanOk && scanVisible && homeOk && homeVisible), shell: Boolean(document.querySelector('.app-sidebar') && document.getElementById('homePanel')) };\n})();\n`);
  writeFileSync(smokeHtmlPath, buildProbePage(dashboardHtml, cookie));

  const browserExecutable = findBrowser();
  const args = [
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
  ];
  browser = spawn(browserExecutable, args, { stdio: ["ignore", "ignore", "pipe"] });
  browser.stderr.setEncoding("utf8");
  browser.stderr.on("data", (chunk) => { browserStderr += chunk; });

  await waitForHttp(`http://${host}:${debugPort}/json/version`, browser, () => browserStderr, 15_000);
  const targets = await (await fetch(`http://${host}:${debugPort}/json/list`, { signal: AbortSignal.timeout(5_000) })).json();
  const target = Array.isArray(targets) ? targets.find((candidate) => candidate.type === "page" && candidate.webSocketDebuggerUrl) : null;
  assert(target?.webSocketDebuggerUrl, `Browser DevTools exposed no page target.\n${browserStderr}`);

  cdpSocket = await connectWebSocket(target.webSocketDebuggerUrl);
  const client = createCdpClient(cdpSocket);
  const checkpoints = [];
  client.on("Runtime.consoleAPICalled", (params) => {
    const values = Array.isArray(params.args) ? params.args.map((arg) => arg.value) : [];
    if (values[0] === "__EMAIL_SHIELD_BOOT_CHECKPOINT__" && typeof values[1] === "string") {
      checkpoints.push(values[1]);
    }
  });
  await Promise.all([client.send("Page.enable"), client.send("Runtime.enable")]);

  const navigation = await client.send("Page.navigate", { url: `${baseUrl}/__email-shield-browser-smoke.html` }, 15_000);
  assert(!navigation.errorText, `Browser navigation failed: ${navigation.errorText}`);

  let result;
  let readyState = "navigation-started";
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    try {
      const snapshot = await evaluate(client, "({ readyState: document.readyState, result: window.__emailShieldBrowserSmokeResult ?? null })");
      readyState = snapshot?.readyState ?? readyState;
      result = snapshot?.result ?? null;
      if (result) break;
    } catch (error) {
      const message = String(error?.message ?? error);
      if (/DevTools command timed out: Runtime\.evaluate/i.test(message)) {
        const lastCheckpoint = checkpoints.at(-1) ?? "none — renderer locked before the first production script completed";
        throw new Error(`Browser renderer became unresponsive during dashboard boot. Last completed production script: ${lastCheckpoint}. Completed checkpoints: ${checkpoints.length}.`);
      }
      if (!/context|navigation|Cannot find context/i.test(message)) throw error;
    }
    await sleep(100);
  }
  assert(result, `The final browser boot probe never executed; document.readyState=${readyState}; last completed production script=${checkpoints.at(-1) ?? "none"}.`);
  assert(result.pass === true, `Executable dashboard boot failed: ${JSON.stringify(result)}`);
  assert(result.errors?.length === 0, `Dashboard boot produced uncaught browser errors: ${JSON.stringify(result.errors)}`);
  assert(result.singleOwner === true, "Browser navigation global no longer has one authoritative router owner.");
  assert(result.routing === true, "Real browser Scan -> Home route navigation failed.");
  assert(result.shell === true, "Real browser application shell did not render.");

  console.log(`Executable browser boot smoke passed with ${browserExecutable}.`);
  console.log(`Uncaught-error capture, single navigation ownership, shell rendering, and Scan/Home routing passed after ${checkpoints.length} production-script checkpoints.`);
} finally {
  try { cdpSocket?.close(); } catch {}
  if (browser && browser.exitCode === null) {
    try { browser.kill(); } catch {}
  }
  if (server && server.exitCode === null) {
    try { server.kill(); } catch {}
  }
  await sleep(150);
  for (const path of [smokeHtmlPath, monitorPath, checkpointPath, probePath]) {
    try { rmSync(path, { force: true }); } catch {}
  }
  try { rmSync(browserProfile, { recursive: true, force: true }); } catch {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch {}
}
