import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
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
      if (response.ok) return response;
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await sleep(100);
  }
  throw new Error(`Timed out waiting for ${url}: ${lastError?.message ?? "unknown error"}\n${stderr()}`);
}

async function waitForDevToolsPort(profileDirectory, processRef, stderr, timeoutMs = 20_000) {
  const activePortPath = join(profileDirectory, "DevToolsActivePort");
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (processRef?.exitCode !== null) {
      throw new Error(`Chromium exited before publishing DevToolsActivePort with code ${processRef.exitCode}.\n${stderr()}`);
    }
    try {
      if (existsSync(activePortPath)) {
        const firstLine = readFileSync(activePortPath, "utf8").split(/\r?\n/, 1)[0]?.trim() ?? "";
        const port = Number.parseInt(firstLine, 10);
        if (Number.isInteger(port) && port > 0 && port <= 65_535) return port;
        lastError = new Error(`Invalid DevToolsActivePort value: ${JSON.stringify(firstLine)}`);
      }
    } catch (error) {
      lastError = error;
    }
    await sleep(50);
  }
  throw new Error(`Timed out waiting for Chromium to publish its authoritative DevTools port: ${lastError?.message ?? "DevToolsActivePort was not created"}\n${stderr()}`);
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
  assert(Number.isInteger(port), "Could not allocate isolated browser-scan server port.");
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

  await evaluate(client, `(() => {
    if (window.__ema8FetchTraceInstalled) return true;
    window.__ema8FetchTraceInstalled = true;
    window.__ema8FetchTrace = [];
    const originalFetch = window.fetch.bind(window);
    window.fetch = async (...args) => {
      const url = typeof args[0] === 'string' ? args[0] : args[0]?.url || '';
      const method = String(args[1]?.method || 'GET').toUpperCase();
      const relevant = url.includes('/messages/');
      const entry = relevant ? { url, method, startedAt: Date.now(), status: null, ok: null, error: null } : null;
      if (entry) window.__ema8FetchTrace.push(entry);
      try {
        const response = await originalFetch(...args);
        if (entry) { entry.status = response.status; entry.ok = response.ok; entry.finishedAt = Date.now(); }
        return response;
      } catch (error) {
        if (entry) { entry.error = error instanceof Error ? error.message : String(error); entry.finishedAt = Date.now(); }
        throw error;
      }
    };
    return true;
  })()`);

  const positiveDecisionToken = await evaluate(client, `(() => {
    window.confirm = () => true;
    const button = [...document.querySelectorAll('.card button[data-action="mark-safe"]')]
      .find((candidate) => !candidate.disabled && candidate.dataset.reviewToken &&
        document.querySelector('[data-action="report-scam"][data-review-token="' + CSS.escape(candidate.dataset.reviewToken) + '"]'));
    if (!button) return null;
    const token = button.dataset.reviewToken;
    button.click();
    return token;
  })()`);
  assert(positiveDecisionToken, `No Mark Safe + Report Scam decision pair was available after the fixture scan. Last state: ${JSON.stringify(snapshot)}`);

  let positiveDecisionState = null;
  const positiveDecisionDeadline = Date.now() + 15_000;
  while (Date.now() < positiveDecisionDeadline) {
    positiveDecisionState = await evaluate(client, `(() => {
      const report = document.querySelector('[data-action="report-scam"][data-review-token="${positiveDecisionToken}"]');
      const safe = document.querySelector('[data-action="mark-safe"][data-review-token="${positiveDecisionToken}"]');
      return {
        reportDisabled: report?.disabled === true,
        reportText: report?.textContent || '',
        safeDisabled: safe?.disabled === true,
        safeText: safe?.textContent || '',
      };
    })()`);
    if (positiveDecisionState?.reportDisabled && positiveDecisionState?.reportText.includes('Campaign decision already saved')) break;
    await sleep(100);
  }
  assert(positiveDecisionState?.safeDisabled === true && positiveDecisionState?.safeText.includes('marked Safe'),
    `Browser Mark Safe did not persist its visible local decision. State: ${JSON.stringify(positiveDecisionState)}`);
  const authoritativeWorkspaceState = await evaluate(client, `(async () => {
    const response = await fetch('/api/accounts/workspace', { headers: { Accept: 'application/json' }, cache: 'no-store' });
    const workspace = await response.json().catch(() => ({}));
    const presentation = workspace?.presentation && typeof workspace.presentation === 'object' ? workspace.presentation : {};
    const entries = [
      ...(Array.isArray(presentation.suspiciousCards) ? presentation.suspiciousCards : []),
      ...(Array.isArray(presentation.diagnosticSummaries) ? presentation.diagnosticSummaries : []),
    ];
    const matching = entries.find((candidate) => candidate?.reviewAction?.token === ${JSON.stringify(positiveDecisionToken)}) || null;
    return {
      responseOk: response.ok,
      selectedAccountId: workspace?.selectedAccountId || null,
      expectedAccountId: ${JSON.stringify(accountId)},
      matchingTokenFound: Boolean(matching),
      reportScamAvailable: matching?.reviewAction?.reportScamAvailable ?? null,
      workspaceEntryCount: entries.length,
    };
  })()`);
  if (positiveDecisionState?.reportDisabled) {
    assert(positiveDecisionState.reportText.includes('Campaign decision already saved'),
      `Retained campaign-decision capability was disabled with the wrong consumer state. State: ${JSON.stringify(positiveDecisionState)} Workspace: ${JSON.stringify(authoritativeWorkspaceState)}`);
  } else {
    assert(positiveDecisionState?.reportText === 'Report Scam to Email Shield',
      `Released campaign-decision capability was not restored truthfully. State: ${JSON.stringify(positiveDecisionState)} Workspace: ${JSON.stringify(authoritativeWorkspaceState)}`);
    await evaluate(client, `(() => {
      window.confirm = () => true;
      document.querySelector('[data-action="report-scam"][data-review-token="${positiveDecisionToken}"]')?.click();
      return true;
    })()`);
    const reportDeadline = Date.now() + 10_000;
    let releasedReportState = null;
    while (Date.now() < reportDeadline) {
      releasedReportState = await evaluate(client, `(() => {
        const report = document.querySelector('[data-action="report-scam"][data-review-token="${positiveDecisionToken}"]');
        const card = report?.closest('.card');
        const status = card?.querySelector('.review-action-status');
        return {
          reportDisabled: report?.disabled === true,
          reportText: report?.textContent || '',
          statusText: status?.textContent || '',
        };
      })()`);
      const reported = releasedReportState?.reportDisabled && /Reported|Campaign protected/.test(releasedReportState.reportText);
      const failedForAnotherReason = !releasedReportState?.reportDisabled && /^Message action failed:/.test(releasedReportState?.statusText || '');
      if (reported || failedForAnotherReason) break;
      await sleep(100);
    }
    const mutationTrace = await evaluate(client, `window.__ema8FetchTrace || []`);
    assert(releasedReportState,
      'Released Report Scam capability did not produce an observable browser state.');
    const replayConflict = /message_action_conflict|already been used|rescan before performing another action/i.test(releasedReportState.statusText || '');
    assert(replayConflict === false,
      `Released campaign-decision capability still hit the stale replay conflict. State: ${JSON.stringify(releasedReportState)} Workspace: ${JSON.stringify(authoritativeWorkspaceState)} Requests: ${JSON.stringify(mutationTrace)}`);
    assert(
      (releasedReportState.reportDisabled && /Reported|Campaign protected/.test(releasedReportState.reportText)) ||
      (!releasedReportState.reportDisabled && /^Message action failed:/.test(releasedReportState.statusText)),
      `Released Report Scam capability never settled to success or an unrelated explicit failure. State: ${JSON.stringify(releasedReportState)} Workspace: ${JSON.stringify(authoritativeWorkspaceState)} Requests: ${JSON.stringify(mutationTrace)}`,
    );
  }

  const blockTarget = await evaluate(client, `(() => {
    window.confirm = () => true;
    const button = [...document.querySelectorAll('.card button[data-action="block-sender"]')]
      .find((candidate) => !candidate.disabled && candidate.dataset.reviewToken);
    if (!button) return null;
    const address = String(button.dataset.address || '').toLowerCase();
    const token = button.dataset.reviewToken || '';
    button.click();
    return { address, token };
  })()`);
  assert(blockTarget?.address && blockTarget?.token, `No protected Block sender control was available after the fixture scan. Last state: ${JSON.stringify(snapshot)}`);

  let blockState = null;
  const blockDeadline = Date.now() + 15_000;
  while (Date.now() < blockDeadline) {
    blockState = await evaluate(client, `(async () => {
      const response = await fetch('/api/accounts/${accountId}/personal-policy', { cache: 'no-store' });
      const policy = await response.json().catch(() => ({}));
      const button = [...document.querySelectorAll('.card button[data-action="block-sender"]')]
        .find((candidate) => candidate.dataset.reviewToken === ${JSON.stringify(blockTarget.token)}) || null;
      return {
        responseOk: response.ok,
        blocked: Array.isArray(policy.blockedSenders) && policy.blockedSenders.includes(${JSON.stringify(blockTarget.address)}),
        buttonDisabled: button?.disabled === true,
        buttonText: button?.textContent || '',
        policyCounts: document.getElementById('policyCounts')?.textContent || '',
        status: document.getElementById('scanMonitorStatus')?.textContent || '',
      };
    })()`);
    if (blockState?.blocked && blockState?.buttonDisabled && blockState?.policyCounts.includes('Blocked senders: 1')) break;
    await sleep(100);
  }

  assert(blockState?.responseOk === true, `Personal Policy could not be re-read after Block. State: ${JSON.stringify(blockState)}`);
  assert(blockState.blocked === true, `Browser Block sender did not persist to encrypted Personal Policy. State: ${JSON.stringify(blockState)}`);
  assert(blockState.buttonDisabled === true && blockState.buttonText.includes('blocked'), `Browser Block sender control did not synchronize after persistence. State: ${JSON.stringify(blockState)}`);
  assert(blockState.policyCounts.includes('Blocked senders: 1'), `Personal Policy UI did not refresh the durable block count. State: ${JSON.stringify(blockState)}`);
  assert(runtimeErrors.length === 0, `Consumer scan produced uncaught browser errors: ${JSON.stringify(runtimeErrors)}`);

  console.log(`Executable consumer scan-results smoke passed with ${executable}.`);
  console.log(`Visible scanned-email rows: ${snapshot.rowCount}.`);
  console.log("Legitimate newsletter + verified unsubscribe UI passed; unsafe HTTP unsubscribe remained non-actionable.");
  console.log("Mark Safe + positive campaign learning reconciled Report Scam without a deterministic capability conflict.");
  console.log(`Protected Block sender persisted and refreshed Personal Policy for ${blockTarget.address}.`);
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