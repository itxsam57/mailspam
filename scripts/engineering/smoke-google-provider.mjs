import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = process.cwd();
const host = "127.0.0.1";
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-google-smoke-data-"));
const browserProfile = mkdtempSync(join(tmpdir(), "email-shield-google-smoke-browser-"));
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
  throw new Error("No Chrome, Chromium, or Edge executable was found for the Google provider smoke.");
}

async function waitForDevToolsPort(profileDirectory, processRef, stderr, timeoutMs = 20_000) {
  const activePortPath = join(profileDirectory, "DevToolsActivePort");
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (processRef?.exitCode !== null) {
      throw new Error(`Chromium exited before publishing DevToolsActivePort with code ${processRef.exitCode}.\n${stderr()}`);
    }
    if (existsSync(activePortPath)) {
      try {
        const port = Number.parseInt(readFileSync(activePortPath, "utf8").split(/\r?\n/, 1)[0]?.trim() ?? "", 10);
        if (Number.isInteger(port) && port > 0 && port <= 65_535) return port;
      } catch (error) {
        // Chromium can briefly hold this file open exclusively on Windows while
        // publishing it. The surrounding loop is already a readiness poll, so
        // EBUSY means "not ready yet" rather than a terminal smoke failure.
        if (error?.code !== "EBUSY") throw error;
      }
    }
    await sleep(50);
  }
  throw new Error(`Timed out waiting for Chromium DevTools port.\n${stderr()}`);
}

async function connectWebSocket(url, timeoutMs = 10_000) {
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

async function waitForValue(client, expression, predicate, label, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  let value;
  while (Date.now() < deadline) {
    value = await evaluate(client, expression);
    if (predicate(value)) return value;
    await sleep(100);
  }
  throw new Error(`${label} did not become ready: ${JSON.stringify(value)}`);
}

try {
  const port = await freePort();
  assert(Number.isInteger(port), "Could not allocate an isolated Email Shield server port.");
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
      EMAIL_SHIELD_GOOGLE_CLIENT_ID: "email-shield-browser-smoke.apps.googleusercontent.com",
      EMAIL_SHIELD_GOOGLE_CLIENT_SECRET: "email-shield-browser-smoke-secret",
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
  assert(!navigation.errorText, `Email Shield browser navigation failed: ${navigation.errorText}`);

  const google = await waitForValue(
    client,
    `(() => {
      const button = document.querySelector('button.consumer-provider[data-consumer-provider="gmail"]');
      return {
        readyState: document.readyState,
        exists: button instanceof HTMLButtonElement,
        disabled: button instanceof HTMLButtonElement ? button.disabled : null,
        configured: button instanceof HTMLButtonElement ? button.dataset.oauthConfigured || null : null,
        owner: typeof window.emailShieldGoogleOAuth?.start === 'function',
        secureFetch: window.emailShieldSecureFetchInstalled === true,
        microsoftVisible: Boolean(document.querySelector('button.consumer-provider[data-consumer-provider="outlook"]')),
      };
    })()`,
    (value) => value?.readyState === "complete" && value?.configured === "true",
    "Configured Google consumer card",
    15_000,
  );

  assert(google.exists === true, "Normal consumer UI did not render Continue with Google.");
  assert(google.disabled === false, "Configured Google consumer card is still natively disabled.");
  assert(google.owner === true, "Google consumer card has no hardened OAuth owner.");
  assert(google.secureFetch === true, "Protected local browser fetch wrapper did not initialize.");
  assert(google.microsoftVisible === false, "Normal consumer UI unexpectedly exposed deferred Microsoft onboarding.");

  await evaluate(client, `(() => {
    window.__emailShieldGoogleSmokeDestination = null;
    window.open = () => ({
      document: { title: '', body: { textContent: '' } },
      location: { replace: (url) => { window.__emailShieldGoogleSmokeDestination = String(url); } },
      close() {},
    });
    const button = document.querySelector('button.consumer-provider[data-consumer-provider="gmail"]');
    if (!(button instanceof HTMLButtonElement)) throw new Error('Google consumer button disappeared before click.');
    button.click();
    return true;
  })()`);

  const destination = await waitForValue(
    client,
    "window.__emailShieldGoogleSmokeDestination",
    (value) => typeof value === "string" && value.length > 0,
    "Google OAuth destination",
    10_000,
  );
  const authorizationUrl = new URL(destination);
  assert(authorizationUrl.protocol === "https:", "Google OAuth click did not produce an HTTPS authorization URL.");
  assert(authorizationUrl.origin === "https://accounts.google.com", `Google OAuth click produced unexpected origin ${authorizationUrl.origin}.`);
  assert(authorizationUrl.searchParams.get("client_id") === "email-shield-browser-smoke.apps.googleusercontent.com", "Google OAuth start did not use the configured application client ID.");
  assert(authorizationUrl.searchParams.get("code_challenge_method") === "S256", "Google OAuth start lost PKCE S256.");

  console.log(`Executable Google consumer entrypoint smoke passed with ${browserExecutable}.`);
  console.log("Continue with Google rendered, stayed actionable, reached the hardened owner, and produced a PKCE Google authorization request.");
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
