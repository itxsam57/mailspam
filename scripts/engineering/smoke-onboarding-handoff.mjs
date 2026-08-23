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

    const permissionStep = document.querySelector('.first-run-step[data-step="permissions_reviewed"]');
    permissionStep?.querySelector('button')?.click();
    await new Promise((resolve) => setTimeout(resolve, 50));
    const permissionNote = document.getElementById('consumerPermissionNote');

    const familyStep = document.querySelector('.first-run-step[data-step="family_option_reviewed"]');
    [...(familyStep?.querySelectorAll('button') || [])].find((button) => button.textContent?.trim() === 'Open')?.click();
    await new Promise((resolve) => setTimeout(resolve, 50));
    const familyNote = document.getElementById('consumerFamilyReviewNote');

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
      permissionReviewAvailable: Boolean(permissionNote && permissionNote.hidden === false),
      permissionText: permissionNote?.textContent || '',
      permissionComplete: permissionStep?.dataset.complete === 'true',
      familyReviewAvailable: Boolean(familyNote && familyNote.hidden === false),
      familyText: familyNote?.textContent || '',
      familyComplete: familyStep?.dataset.complete === 'true',
      settingsVisible: settings?.hidden === false,
      guidanceVisible: Boolean(guidance && guidance.hidden === false),
      guidanceTextPresent: Boolean(guidance?.textContent?.includes('Connect a mailbox to continue')),
      providerGridPresent: Boolean(grid),
      providerFocused: typeof focusedProvider === 'string' && focusedProvider.length > 0,
      focusedProvider,
      sensitivityComplete: sensitivityStep?.dataset.complete === 'true',
      notificationSurfacePresent: Boolean(document.body.textContent?.includes('Notification privacy')),
      richerNotificationControlPresent: Boolean(document.querySelector('[id$="RicherNotifications"]')),
      mediaScriptMounted: [...document.scripts].some((script) => /media-authenticity\.js$/i.test(script.src || '')),
      mediaToolPresent: Boolean(document.body.textContent?.includes('Media Authenticity')),
    };
  })()`);

  assert(result.accountsBefore === 0 && result.accountsAfter === 0, `Onboarding smoke expected zero connected mailboxes: ${JSON.stringify(result)}`);
  assert(result.permissionReviewAvailable === true && /Gmail: OpenID identity \+ Gmail modify access/.test(result.permissionText) && /Microsoft: identity \+ Mail\.ReadWrite/.test(result.permissionText), `Pre-connect provider permission review was not truthful: ${JSON.stringify(result)}`);
  assert(result.permissionComplete === false, `Permission review was incorrectly persisted without a mailbox: ${JSON.stringify(result)}`);
  assert(result.familyReviewAvailable === true && /paid Family entitlement/i.test(result.familyText), `Pre-connect Family review/entitlement boundary was not visible: ${JSON.stringify(result)}`);
  assert(result.familyComplete === false, `Family setup was incorrectly persisted without a mailbox: ${JSON.stringify(result)}`);
  assert(result.settingsVisible === true, `Sensitivity prerequisite did not route to Mailboxes & Settings: ${JSON.stringify(result)}`);
  assert(result.guidanceVisible === true && result.guidanceTextPresent === true, `Provider setup guidance did not become visible: ${JSON.stringify(result)}`);
  assert(result.providerGridPresent === true && result.providerFocused === true, `Provider choices were not surfaced/focused: ${JSON.stringify(result)}`);
  assert(result.focusedProvider !== 'outlook', `Postponed Outlook became reachable in normal consumer setup: ${JSON.stringify(result)}`);
  assert(result.sensitivityComplete === false, `Sensitivity was incorrectly credited without a connected mailbox: ${JSON.stringify(result)}`);
  assert(result.notificationSurfacePresent === false && result.richerNotificationControlPresent === false, `Release UI still advertised an undelivered notification contract: ${JSON.stringify(result)}`);
  assert(result.mediaScriptMounted === false && result.mediaToolPresent === false, `Release UI still advertised unavailable Media Authenticity: ${JSON.stringify(result)}`);

  const connectionStarted = await evaluate(client, `(() => {
    const provider = document.getElementById('providerSelect');
    const mode = document.getElementById('modeSelect');
    const connect = document.getElementById('connectBtn');
    if (!provider || !mode || !connect) return false;
    provider.value = 'gmail';
    provider.dispatchEvent(new Event('change', { bubbles: true }));
    mode.value = 'fixture';
    mode.dispatchEvent(new Event('change', { bubbles: true }));
    connect.click();
    return true;
  })()`);
  assert(connectionStarted === true, "Onboarding smoke could not start the fixture mailbox connection.");

  const statusDeadline = Date.now() + 15_000;
  let mailboxStatus = null;
  while (Date.now() < statusDeadline) {
    try {
      mailboxStatus = await evaluate(client, `(() => {
        const selected = document.querySelector('#accountsList .account-chip.active');
        const status = document.getElementById('homeProtectionState');
        const indicator = status?.closest('.home-protection-state');
        if (!selected || !status || !indicator) return null;
        window.emailShieldNavigate?.('home', { focus: false });
        return {
          accountId: selected.dataset.id || null,
          rowReachability: selected.dataset.reachability || null,
          text: status.textContent?.trim() || '',
          indicatorReachability: indicator.dataset.reachability || null,
        };
      })()`);
      if (mailboxStatus?.rowReachability && mailboxStatus?.text && mailboxStatus?.accountId) break;
    } catch {}
    await sleep(100);
  }

  const expectedStatusText = {
    checking: 'Checking mailbox connection',
    reachable: 'Mailbox connection verified',
    unavailable: 'Mailbox connection needs attention',
    unknown: 'Mailbox status unavailable',
  };
  assert(mailboxStatus && Object.hasOwn(expectedStatusText, mailboxStatus.rowReachability), `Connected mailbox exposed no sanitized reachability state: ${JSON.stringify(mailboxStatus)}`);
  assert(mailboxStatus.text === expectedStatusText[mailboxStatus.rowReachability], `Home did not render the selected mailbox reachability truthfully: ${JSON.stringify(mailboxStatus)}`);
  assert(mailboxStatus.indicatorReachability === mailboxStatus.rowReachability, `Home indicator did not follow the canonical selected mailbox reachability: ${JSON.stringify(mailboxStatus)}`);
  assert(!/protection ready/i.test(mailboxStatus.text), `Home inferred protection from mailbox selection: ${JSON.stringify(mailboxStatus)}`);

  const continuousDeadline = Date.now() + 15_000;
  let continuousBefore = null;
  while (Date.now() < continuousDeadline) {
    continuousBefore = await evaluate(client, `(() => {
      window.emailShieldNavigate?.('protection', { focus: false });
      const panel = document.getElementById('backgroundProtection');
      const toggle = document.getElementById('backgroundToggle');
      const status = document.getElementById('backgroundStatus');
      return {
        heading: panel?.querySelector('h3')?.textContent?.trim() || '',
        pressed: toggle?.getAttribute('aria-pressed') || '',
        disabled: toggle?.disabled === true,
        status: status?.textContent || '',
      };
    })()`);
    if (continuousBefore?.heading === 'Continuous Protection' && continuousBefore?.disabled === false && /metadata checkpoint fallback/i.test(continuousBefore.status)) break;
    await sleep(100);
  }
  assert(continuousBefore?.heading === 'Continuous Protection', `Continuous Protection control was not composed in the real UI: ${JSON.stringify(continuousBefore)}`);
  assert(continuousBefore?.pressed === 'false', `Fresh fixture unexpectedly started with Continuous Protection enabled: ${JSON.stringify(continuousBefore)}`);
  assert(/Provider-event protection/i.test(continuousBefore?.status || '') && /metadata checkpoint fallback/i.test(continuousBefore?.status || ''), `Automatic-protection capability truth was missing: ${JSON.stringify(continuousBefore)}`);

  const toggled = await evaluate(client, `(() => {
    const toggle = document.getElementById('backgroundToggle');
    if (!(toggle instanceof HTMLButtonElement) || toggle.disabled) return false;
    toggle.click();
    return true;
  })()`);
  assert(toggled === true, `Could not enable Continuous Protection from the real consumer control: ${JSON.stringify(continuousBefore)}`);

  const enabledDeadline = Date.now() + 15_000;
  let continuousAfter = null;
  while (Date.now() < enabledDeadline) {
    continuousAfter = await evaluate(client, `(async () => {
      const toggle = document.getElementById('backgroundToggle');
      const status = document.getElementById('backgroundStatus');
      const response = await fetch('/api/accounts/${mailboxStatus.accountId}/background-protection', { cache: 'no-store' });
      const body = await response.json().catch(() => ({}));
      return {
        ok: response.ok,
        pressed: toggle?.getAttribute('aria-pressed') || '',
        enabled: body.enabled === true,
        automaticEnabled: body.automaticProtection?.automaticProcessingEnabled === true,
        providerEvents: body.automaticProtection?.providerEvents || null,
        fallback: body.automaticProtection?.metadataCheckpointFallback || null,
        status: status?.textContent || '',
      };
    })()`);
    if (continuousAfter?.ok && continuousAfter?.pressed === 'true' && continuousAfter?.enabled && continuousAfter?.automaticEnabled) break;
    await sleep(100);
  }
  assert(continuousAfter?.enabled === true && continuousAfter?.automaticEnabled === true, `Persisted switch did not authorize automatic protection end-to-end: ${JSON.stringify(continuousAfter)}`);
  assert(continuousAfter?.providerEvents === 'not_configured_in_desktop_runtime' && continuousAfter?.fallback === 'available', `Continuous Protection overstated provider-event capability or lost metadata fallback: ${JSON.stringify(continuousAfter)}`);

  const healthStarted = await evaluate(client, `(() => {
    window.emailShieldNavigate?.('protection', { focus: false });
    const button = document.getElementById('consumerRunHealth');
    if (!(button instanceof HTMLButtonElement)) return false;
    button.click();
    return true;
  })()`);
  assert(healthStarted === true, "Could not start real fixture Health check for Activity acceptance.");

  const healthDeadline = Date.now() + 30_000;
  let healthComplete = false;
  while (Date.now() < healthDeadline) {
    healthComplete = await evaluate(client, `/Health check complete/i.test(document.getElementById('consumerHealthStatus')?.textContent || '')`).catch(() => false);
    if (healthComplete) break;
    await sleep(100);
  }
  assert(healthComplete, `Fixture Health did not complete before Activity acceptance. Server stderr:\n${serverStderr}`);

  const activityDeadline = Date.now() + 15_000;
  let activityState = null;
  while (Date.now() < activityDeadline) {
    activityState = await evaluate(client, `(async () => {
      window.emailShieldNavigate?.('history', { focus: false });
      document.getElementById('consumerRefreshActivity')?.click();
      await new Promise((resolve) => setTimeout(resolve, 75));
      const details = document.querySelector('#consumerActivityList [data-activity-details]');
      return {
        present: Boolean(details),
        summary: details?.querySelector('summary')?.textContent?.trim() || '',
        text: details?.textContent || '',
        listText: document.getElementById('consumerActivityList')?.textContent || '',
      };
    })()`);
    if (activityState?.present) break;
    await sleep(100);
  }
  assert(activityState?.present === true && activityState?.summary === 'Why Email Shield recorded this', `Activity explanation disclosure was missing: ${JSON.stringify(activityState)}`);
  assert(/health check/i.test(activityState?.listText || '') && /reason codes:/i.test(activityState?.text || ''), `Activity disclosure did not explain the real Health activity privacy-safely: ${JSON.stringify(activityState)}`);

  console.log(`Executable final consumer onboarding/protection smoke passed with ${browserExecutable}.`);
  console.log("Pre-connect permissions and Family review were available without false completion or entitlement bypass; unsupported release surfaces were absent.");
  console.log("One persisted Continuous Protection switch authorized scheduled/provider-change automation while truthfully reporting provider-event availability and metadata fallback.");
  console.log("A real Health action produced an Activity row with an accessible privacy-safe reason disclosure.");
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
