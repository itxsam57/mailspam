import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = process.cwd();
const host = "127.0.0.1";
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-browser-scan-data-"));
const browserProfile = mkdtempSync(join(tmpdir(), "email-shield-browser-scan-profile-"));
let server;
let browser;
let socket;
let serverStderr = "";
let browserStderr = "";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const sleep = (ms) => new Promise((resolveWait) => setTimeout(resolveWait, ms));

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
  for (const command of process.platform === "win32"
    ? ["chrome.exe", "msedge.exe"]
    : ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge"]) {
    const located = findOnPath(command);
    if (located) return located;
  }
  throw new Error("No Chrome, Chromium, or Edge executable was found for the consumer scan browser gate.");
}

async function connectWebSocket(url, timeoutMs = 10_000) {
  assert(typeof WebSocket === "function", "Node.js WebSocket support is required for the browser gate.");
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
    throw new Error(`Browser evaluation failed: ${result.exceptionDetails.exception?.description ?? result.exceptionDetails.text ?? "unknown exception"}`);
  }
  return result.result?.value;
}

try {
  const port = await freePort();
  const debugPort = await freePort();
  assert(Number.isInteger(port) && Number.isInteger(debugPort), "Could not allocate isolated browser-scan ports.");
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
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  server.stderr.setEncoding("utf8");
  server.stderr.on("data", (chunk) => { serverStderr += chunk; });
  await waitForHttp(baseUrl, server, () => serverStderr);

  const executable = findBrowser();
  browser = spawn(executable, [
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
  const target = Array.isArray(targets) ? targets.find((item) => item.type === "page" && item.webSocketDebuggerUrl) : null;
  assert(target?.webSocketDebuggerUrl, `Browser DevTools exposed no page target.\n${browserStderr}`);

  socket = await connectWebSocket(target.webSocketDebuggerUrl);
  const client = createClient(socket);
  const runtimeErrors = [];
  client.on("Runtime.exceptionThrown", ({ exceptionDetails }) => {
    runtimeErrors.push(exceptionDetails?.exception?.description ?? exceptionDetails?.text ?? "browser exception");
  });
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
      document.getElementById('consumerScanMessageFeed') &&
      document.getElementById('fullScanBtn')
    )`).catch(() => false);
    if (ready) break;
    await sleep(100);
  }
  assert(ready, "Consumer scan browser gate could not reach the fully initialized dashboard.");

  const accountId = await evaluate(client, `(async () => {
    const response = await fetch('/api/accounts/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'gmail', mode: 'fixture', label: 'browser-scan-fixture' }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || typeof body.accountId !== 'string') throw new Error(body.error || 'Fixture account connection failed.');
    await refreshAccounts();
    window.emailShieldSelectAccount(body.accountId, { remember: false });
    window.emailShieldNavigate('scan', { focus: false });
    document.getElementById('fullScanBtn').click();
    return body.accountId;
  })()`, 20_000);
  assert(typeof accountId === "string" && accountId.length > 0, "Browser fixture account did not return an account id.");

  let snapshot = null;
  const scanDeadline = Date.now() + 45_000;
  while (Date.now() < scanDeadline) {
    snapshot = await evaluate(client, `(() => {
      const rows = [...document.querySelectorAll('#consumerScanMessageFeed [data-message-row="true"]')];
      const newsletter = rows.find((row) => row.querySelector('.safe-subject')?.textContent?.trim() === 'Your weekly digest') || null;
      const malicious = rows.find((row) => row.querySelector('.safe-subject')?.textContent?.includes("You're still subscribed") ) || null;
      const unsubscribe = newsletter?.querySelector('button[data-action="unsubscribe"]') || null;
      return {
        rowCount: rows.length,
        newsletterVisible: Boolean(newsletter),
        newsletterSafe: Boolean(newsletter?.querySelector('.consumer-scan-verdict.safe')),
        unsubscribeVisible: Boolean(unsubscribe),
        unsubscribeMethod: unsubscribe?.dataset.unsubscribeMethod || null,
        rawDestinationExposed: Boolean(newsletter?.textContent?.includes('realnewsco.com/unsubscribe')),
        maliciousVisible: Boolean(malicious),
        maliciousUnsafeActionVisible: Boolean(malicious?.querySelector('button[data-action="unsubscribe"]')),
        status: document.getElementById('scanMonitorStatus')?.textContent || '',
      };
    })()`);
    if (snapshot?.newsletterVisible && snapshot?.unsubscribeVisible && snapshot?.maliciousVisible) break;
    await sleep(100);
  }

  assert(snapshot?.rowCount > 0, `Consumer scan page rendered no examined emails. Last state: ${JSON.stringify(snapshot)}`);
  assert(snapshot.newsletterVisible === true, `Legitimate newsletter was not visible on the Scan page. Last state: ${JSON.stringify(snapshot)}`);
  assert(snapshot.newsletterSafe === true, `Legitimate authenticated newsletter was not presented as Safe. Last state: ${JSON.stringify(snapshot)}`);
  assert(snapshot.unsubscribeVisible === true, `Legitimate newsletter had no visible Unsubscribe action. Last state: ${JSON.stringify(snapshot)}`);
  assert(snapshot.unsubscribeMethod === "one_click_post", `Legitimate newsletter lost its verified one-click method. Last state: ${JSON.stringify(snapshot)}`);
  assert(snapshot.rawDestinationExposed === false, "Consumer scan page exposed the raw unsubscribe destination.");
  assert(snapshot.maliciousVisible === true, `Malicious newsletter control was not visible for comparison. Last state: ${JSON.stringify(snapshot)}`);
  assert(snapshot.maliciousUnsafeActionVisible === false, "Unsafe HTTP unsubscribe destination was rendered as an actionable consumer control.");
  assert(runtimeErrors.length === 0, `Consumer scan produced uncaught browser errors: ${JSON.stringify(runtimeErrors)}`);

  console.log(`Executable consumer scan-results smoke passed with ${executable}.`);
  console.log(`Visible scanned-email rows: ${snapshot.rowCount}.`);
  console.log("Legitimate newsletter + verified unsubscribe UI passed; unsafe HTTP unsubscribe remained non-actionable.");
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
