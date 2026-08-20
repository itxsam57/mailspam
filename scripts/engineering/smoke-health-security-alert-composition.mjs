import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = process.cwd();
const host = "127.0.0.1";
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-health-alerts-data-"));
const browserProfile = mkdtempSync(join(tmpdir(), "email-shield-health-alerts-profile-"));
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
  return !processRef || processRef.exitCode !== null || processRef.signalCode !== null;
}

async function stopChild(processRef, label) {
  if (childProcessExited(processRef)) return;
  try { processRef.kill(); } catch {}
  const gracefulDeadline = Date.now() + 3_000;
  while (!childProcessExited(processRef) && Date.now() < gracefulDeadline) await sleep(50);
  if (childProcessExited(processRef)) return;
  try { processRef.kill("SIGKILL"); } catch {}
  const forcedDeadline = Date.now() + 3_000;
  while (!childProcessExited(processRef) && Date.now() < forcedDeadline) await sleep(50);
  assert(childProcessExited(processRef), `${label} did not exit during Health alert teardown.`);
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
  throw new Error(`Timed out waiting for ${url}: ${lastError?.message ?? "unknown error"}`);
}

async function waitForDevToolsPort(profileDirectory, processRef, stderr, timeoutMs = 20_000) {
  const activePortPath = join(profileDirectory, "DevToolsActivePort");
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (childProcessExited(processRef)) throw new Error(`Chromium exited before publishing DevToolsActivePort.\n${stderr()}`);
    try {
      if (existsSync(activePortPath)) {
        const firstLine = readFileSync(activePortPath, "utf8").split(/\r?\n/, 1)[0]?.trim() ?? "";
        const port = Number.parseInt(firstLine, 10);
        if (Number.isInteger(port) && port > 0 && port <= 65_535) return port;
        lastError = new Error(`Invalid DevToolsActivePort value: ${JSON.stringify(firstLine)}`);
      }
    } catch (error) { lastError = error; }
    await sleep(50);
  }
  throw new Error(`Timed out waiting for Chromium DevTools: ${lastError?.message ?? "port unavailable"}`);
}

function findOnPath(command) {
  const result = spawnSync(process.platform === "win32" ? "where" : "which", [command], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  return result.status === 0 ? result.stdout.split(/\r?\n/).map((line) => line.trim()).find(Boolean) ?? null : null;
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
  const commands = process.platform === "win32"
    ? ["chrome.exe", "msedge.exe"]
    : ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge"];
  for (const command of commands) {
    const found = findOnPath(command);
    if (found) return found;
  }
  throw new Error("No Chrome, Chromium, or Edge executable was found for the Health security-alert gate.");
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
        const timer = setTimeout(() => { pending.delete(id); reject(new Error(`DevTools command timed out: ${method}`)); }, timeoutMs);
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
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description ?? result.exceptionDetails.text ?? "Browser evaluation failed");
  return result.result?.value;
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
      EMAIL_SHIELD_ENABLE_HEALTH_SECURITY_ALERT_FIXTURES: "1",
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
      document.getElementById('consumerRunHealth')
    )`).catch(() => false);
    if (ready) break;
    await sleep(100);
  }
  assert(ready, "Health security-alert browser gate could not reach the initialized dashboard.");

  const accountId = await evaluate(client, `(async () => {
    const response = await fetch('/api/accounts/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'gmail', mode: 'fixture', label: 'health-alert-composition-fixture' }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || typeof body.accountId !== 'string') throw new Error(body.error || 'Fixture connection failed.');
    await refreshAccounts();
    window.emailShieldSelectAccount(body.accountId, { remember: false });
    window.emailShieldNavigate('protection', { focus: false });
    document.getElementById('consumerRunHealth').click();
    return body.accountId;
  })()`, 20_000);
  assert(typeof accountId === "string" && accountId, "Health alert fixture account was not created.");

  let observed = null;
  const healthDeadline = Date.now() + 35_000;
  while (Date.now() < healthDeadline) {
    observed = await evaluate(client, `(() => {
      const status = document.getElementById('consumerHealthStatus')?.textContent?.trim() || '';
      const summary = [...document.querySelectorAll('#consumerHealthSummary .consumer-stat')].map((item) => ({
        label: item.querySelector('span')?.textContent?.trim() || '',
        value: item.querySelector('strong')?.textContent?.trim() || '',
      }));
      const rows = [...document.querySelectorAll('#consumerMailboxSecurity .consumer-list-item')].map((row) => ({
        title: row.querySelector('strong')?.textContent?.trim() || '',
        detail: row.querySelector('.hint')?.textContent?.trim() || '',
        severity: row.querySelector('.consumer-chip')?.textContent?.trim() || '',
      }));
      const google = rows.filter((row) => row.title.startsWith('Google · '));
      return {
        status,
        mailboxState: summary.find((item) => item.label === 'Mailbox state')?.value || '',
        google,
        securityText: document.getElementById('consumerMailboxSecurity')?.textContent || '',
      };
    })()`);
    if (/Health check complete/i.test(observed?.status || '') && observed?.google?.length >= 2) break;
    await sleep(100);
  }

  assert(/Health check complete/i.test(observed?.status || ''), `Health alert check did not complete. State: ${JSON.stringify(observed)}`);
  assert(observed.mailboxState === "attention", `Authenticated provider alerts did not preserve truthful attention state. State: ${JSON.stringify(observed)}`);
  assert(observed.google.length === 2, `Expected two composed Google security-alert rows, got ${observed.google.length}. State: ${JSON.stringify(observed)}`);

  const signatures = new Set(observed.google.map((row) => `${row.title}\n${row.detail}`));
  assert(signatures.size === 2, `Distinct provider alert classes remained visually indistinguishable. State: ${JSON.stringify(observed)}`);
  const signIn = observed.google.find((row) => /new sign-in/i.test(row.title));
  const password = observed.google.find((row) => /password change/i.test(row.title));
  assert(signIn, `New sign-in alert group was not visibly identified. State: ${JSON.stringify(observed)}`);
  assert(password, `Password-change alert group was not visibly identified. State: ${JSON.stringify(observed)}`);
  assert(/2 distinct authenticated new sign-in observations were/i.test(signIn.detail), `Same-class sign-in alerts were not grouped with a truthful count. State: ${JSON.stringify(signIn)}`);
  assert(/1 authenticated password change observation was/i.test(password.detail), `Password-change alert count was not truthful. State: ${JSON.stringify(password)}`);
  assert(observed.google.every((row) => row.severity === "warning"), `Composed provider alerts lost warning severity. State: ${JSON.stringify(observed.google)}`);
  assert(observed.google.every((row) => /official app or website directly/i.test(row.detail)), `Safe official-site guidance was lost. State: ${JSON.stringify(observed.google)}`);
  assert(!/Security alert: new sign-in|New sign-in on your account|Password changed/.test(observed.securityText), `Raw fixture subjects leaked into Health presentation. State: ${JSON.stringify(observed)}`);
  assert(runtimeErrors.length === 0, `Health security-alert composition produced uncaught browser errors: ${JSON.stringify(runtimeErrors)}`);

  console.log(`Executable Health security-alert composition smoke passed with ${executable}.`);
  console.log(`Three authenticated provider events rendered as ${observed.google.length} distinct consumer warning groups while mailbox state remained attention.`);
} catch (error) {
  console.error(`FAIL: ${error.message}`);
  if (serverStderr.trim()) console.error(`Server stderr:\n${serverStderr.trim()}`);
  if (browserStderr.trim()) console.error(`Browser stderr:\n${browserStderr.trim()}`);
  process.exitCode = 1;
} finally {
  try { socket?.close(); } catch {}
  await stopChild(browser, "Chromium");
  await stopChild(server, "Email Shield server");
  rmSync(browserProfile, { recursive: true, force: true });
  rmSync(dataDir, { recursive: true, force: true });
}
