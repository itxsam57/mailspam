import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

const root = process.cwd();
const host = "127.0.0.1";
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-browser-smoke-data-"));
const browserProfile = mkdtempSync(join(tmpdir(), "email-shield-browser-smoke-profile-"));
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

function openingTag(html, marker) {
  const markerIndex = html.indexOf(marker);
  if (markerIndex < 0) return "";
  const start = html.lastIndexOf("<", markerIndex);
  const end = html.indexOf(">", markerIndex);
  return start >= 0 && end > markerIndex ? html.slice(start, end + 1) : "";
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
  assert(result.stdout.includes('data-email-shield-router-ready="1"'), "The real browser never reached the router-ready contract. A boot script failed or returned before router installation completed.");
  assert(result.stdout.includes('class="app-sidebar"'), "The real browser did not construct the application sidebar.");
  assert(result.stdout.includes('id="homePanel"'), "The real browser did not construct the Home panel.");
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

  const browser = findBrowser();
  const homeHtml = runBrowser(browser, `${baseUrl}/#home`);
  const homeTag = openingTag(homeHtml, 'data-route="home"');
  assert(homeTag && !/\shidden(?:=|\s|>)/.test(homeTag), `Home was not the visible initial route in the real browser: ${homeTag}`);

  const scanHtml = runBrowser(browser, `${baseUrl}/#scan`);
  const scanTag = openingTag(scanHtml, 'data-route="scan"');
  assert(scanTag && !/\shidden(?:=|\s|>)/.test(scanTag), `Scan routing did not initialize from the URL hash in the real browser: ${scanTag}`);

  console.log(`Executable browser boot smoke passed with ${browser}.`);
  console.log("Real DOM boot, router readiness, Home rendering, and Scan hash routing passed.");
} finally {
  if (server && server.exitCode === null) {
    try { server.kill(); } catch {}
  }
  await sleep(150);
  try { rmSync(browserProfile, { recursive: true, force: true }); } catch {}
  try { rmSync(dataDir, { recursive: true, force: true }); } catch {}
}
