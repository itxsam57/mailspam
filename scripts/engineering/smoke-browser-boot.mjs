import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

const root = process.cwd();
const host = "127.0.0.1";
const webDir = resolve(root, "web");
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-browser-smoke-data-"));
const browserProfile = mkdtempSync(join(tmpdir(), "email-shield-browser-smoke-profile-"));
const smokeHtmlPath = join(webDir, "__email-shield-browser-smoke.html");
const monitorPath = join(webDir, "__email-shield-browser-smoke-monitor.js");
const probePath = join(webDir, "__email-shield-browser-smoke-probe.js");
let server;
let serverStderr = "";

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

async function waitForServer(baseUrl, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (server?.exitCode !== null) {
      throw new Error(`Server exited before browser smoke readiness with code ${server.exitCode}.\n${serverStderr}`);
    }
    try {
      const response = await fetch(baseUrl, { signal: AbortSignal.timeout(2_000) });
      if (response.ok) return;
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await sleep(150);
  }
  throw new Error(`Server did not become ready for browser smoke: ${lastError?.message ?? "unknown error"}\n${serverStderr}`);
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
  const withProbe = withMonitor.replace("</body>", `${probeScript}</body>`);
  assert(withProbe !== withMonitor, "Browser smoke could not append its final deferred boot probe.");
  return withProbe;
}

function runBrowser(browser, url) {
  const result = spawnSync(browser, [
    "--headless=new",
    `--user-data-dir=${browserProfile}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-sync",
    "--disable-dev-shm-usage",
    "--metrics-recording-only",
    "--dump-dom",
    url,
  ], {
    cwd: dirname(browser),
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 16 * 1024 * 1024,
  });
  assert(!result.error, `Headless browser failed to execute: ${result.error?.message ?? "unknown error"}`);
  assert(result.status === 0, `Headless browser exited ${result.status}.\n${result.stderr || ""}`);
  return result.stdout;
}

try {
  const port = await freePort();
  assert(Number.isInteger(port), "Could not allocate an isolated browser-smoke server port.");
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
  await waitForServer(baseUrl);

  const dashboardResponse = await fetch(baseUrl, { signal: AbortSignal.timeout(5_000) });
  const dashboardHtml = await dashboardResponse.text();
  const cookie = dashboardResponse.headers.get("set-cookie")?.split(";", 1)[0] ?? "";
  assert(dashboardResponse.ok, `Dashboard returned HTTP ${dashboardResponse.status} while preparing browser smoke.`);
  assert(cookie.startsWith("email_shield_local_session="), "Browser smoke could not obtain the protected local dashboard session.");

  writeFileSync(monitorPath, `window.__emailShieldBrowserSmokeErrors=[];\nwindow.addEventListener('error',(event)=>window.__emailShieldBrowserSmokeErrors.push(String(event.error?.stack||event.message||'browser error')));\nwindow.addEventListener('unhandledrejection',(event)=>window.__emailShieldBrowserSmokeErrors.push(String(event.reason?.stack||event.reason||'unhandled rejection')));\n`);
  writeFileSync(probePath, `(() => {\n  const errors = Array.isArray(window.__emailShieldBrowserSmokeErrors) ? window.__emailShieldBrowserSmokeErrors : ['error monitor missing'];\n  let singleOwner = false; let scanOk = false; let scanVisible = false; let homeOk = false; let homeVisible = false;\n  try {\n    singleOwner = typeof window.emailShieldNavigate === 'function' && window.emailShieldRouter && window.emailShieldNavigate === window.emailShieldRouter.navigate;\n    scanOk = window.emailShieldNavigate?.('scan', { focus: false }) === true;\n    scanVisible = document.querySelector('.app-route[data-route="scan"]')?.hidden === false;\n    homeOk = window.emailShieldNavigate?.('home', { focus: false }) === true;\n    homeVisible = document.querySelector('.app-route[data-route="home"]')?.hidden === false;\n  } catch (error) { errors.push(String(error?.stack || error)); }\n  const pass = errors.length === 0 && singleOwner && scanOk && scanVisible && homeOk && homeVisible;\n  document.documentElement.dataset.emailShieldBrowserSmoke = pass ? 'pass' : 'fail';\n  document.documentElement.dataset.emailShieldBrowserSmokeErrors = String(errors.length);\n  document.documentElement.dataset.emailShieldBrowserSmokeSingleOwner = String(Boolean(singleOwner));\n  document.documentElement.dataset.emailShieldBrowserSmokeRouting = String(Boolean(scanOk && scanVisible && homeOk && homeVisible));\n})();\n`);
  writeFileSync(smokeHtmlPath, buildProbePage(dashboardHtml, cookie));

  const browser = findBrowser();
  const rendered = runBrowser(browser, `${baseUrl}/__email-shield-browser-smoke.html`);
  assert(rendered.includes('data-email-shield-browser-smoke="pass"'), "The executable dashboard boot contract failed in a real browser.");
  assert(rendered.includes('data-email-shield-browser-smoke-errors="0"'), "The executable dashboard boot produced an uncaught JavaScript error or unhandled rejection.");
  assert(rendered.includes('data-email-shield-browser-smoke-single-owner="true"'), "The real browser does not have one authoritative navigation function; app-shell/ui-router ownership regressed.");
  assert(rendered.includes('data-email-shield-browser-smoke-routing="true"'), "The real browser could not navigate Scan -> Home through the public router.");
  assert(rendered.includes('class="app-sidebar"') && rendered.includes('id="homePanel"'), "The real browser did not construct the application shell.");

  console.log(`Executable browser boot smoke passed with ${browser}.`);
  console.log("Uncaught-error capture, single navigation ownership, shell rendering, and Scan/Home routing passed.");
} finally {
  if (server && server.exitCode === null) {
    try { server.kill(); } catch {}
  }
  await sleep(150);
  for (const path of [smokeHtmlPath, monitorPath, probePath]) {
    try { rmSync(path, { force: true }); } catch {}
  }
  try { rmSync(browserProfile, { recursive: true, force: true }); } catch {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch {}
}
