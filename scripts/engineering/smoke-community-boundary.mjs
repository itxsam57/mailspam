import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = process.cwd();
const host = "127.0.0.1";
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-community-boundary-data-"));
const browserProfiles = [];
let server;
let serverStderr = "";

function assert(condition, message) {
  if (!condition) throw new Error(message);
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

async function waitForHttp(url, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (server?.exitCode !== null) {
      throw new Error(`Desktop server exited before ${url} became ready with code ${server.exitCode}.\n${serverStderr}`);
    }
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(2_000) });
      if (response.ok) return;
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  throw new Error(`Timed out waiting for ${url}: ${lastError?.message ?? "unknown error"}\n${serverStderr}`);
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
  throw new Error("No Chrome, Chromium, or Edge executable was found for the Community boundary smoke.");
}

function dumpDom(browserExecutable, url, label) {
  const profile = mkdtempSync(join(tmpdir(), "email-shield-community-boundary-browser-"));
  browserProfiles.push(profile);
  const result = spawnSync(browserExecutable, [
    "--headless=new",
    "--dump-dom",
    "--virtual-time-budget=6000",
    `--user-data-dir=${profile}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-sync",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    url,
  ], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
    timeout: 30_000,
  });
  if (result.error) throw result.error;
  assert(result.status === 0, `${label} Chromium dump failed with exit ${result.status}.\n${result.stderr ?? ""}`);
  assert(result.stdout.includes("Email Shield"), `${label} Chromium dump did not render Email Shield.`);
  return result.stdout;
}

function tagById(dom, id) {
  const escaped = id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return dom.match(new RegExp(`<[^>]+\\bid=["']${escaped}["'][^>]*>`, "i"))?.[0] ?? "";
}

function routeTag(dom, route) {
  const escaped = route.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return dom.match(new RegExp(`<section\\b[^>]*\\bdata-route=["']${escaped}["'][^>]*>`, "i"))?.[0] ?? "";
}

try {
  const port = await freePort();
  assert(Number.isInteger(port), "Could not allocate the Community boundary server port.");
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
  await waitForHttp(baseUrl);

  const browserExecutable = findBrowser();

  const consumerDom = dumpDom(browserExecutable, `${baseUrl}/#community`, "Consumer retired-route");
  assert(!consumerDom.includes('data-route-target="community"'), "Consumer DOM still exposes a Community navigation control.");
  assert(!consumerDom.includes('data-route="community"'), "Consumer DOM still exposes a Community route container.");
  const homeRoute = routeTag(consumerDom, "home");
  assert(homeRoute && !/\bhidden\b/i.test(homeRoute), "Direct #community navigation did not resolve to visible Home.");
  const consumerOperations = tagById(consumerDom, "operationsPanel");
  assert(consumerOperations && /\bhidden\b/i.test(consumerOperations), "Operations diagnostics became visible without explicit developer UI request.");
  assert(!/data-email-shield-developer-enabled=["']true["']/i.test(consumerOperations), "Consumer operations diagnostics acquired developer entitlement unexpectedly.");

  const developerDom = dumpDom(browserExecutable, `${baseUrl}/?developer=1#settings`, "Developer diagnostics");
  assert(!developerDom.includes('data-route-target="community"'), "Developer DOM revived the retired Community navigation control.");
  assert(!developerDom.includes('data-route="community"'), "Developer DOM revived the retired Community route container.");
  const settingsRoute = routeTag(developerDom, "settings");
  assert(settingsRoute && !/\bhidden\b/i.test(settingsRoute), "Explicit developer diagnostics did not remain on visible Settings.");
  const developerOperations = tagById(developerDom, "operationsPanel");
  assert(developerOperations && !/\bhidden\b/i.test(developerOperations), "Entitled developer diagnostics stayed hidden.");
  assert(/data-email-shield-developer-enabled=["']true["']/i.test(developerOperations), "Entitled developer diagnostics omitted their resolved entitlement marker.");
  assert(developerDom.includes("Aggregate operations refreshed"), "Entitled operations diagnostics did not complete their aggregate snapshot load.");
  assert(developerDom.includes("Feed:"), "Entitled operations diagnostics did not render the privacy-safe aggregate summary.");

  console.log(`Executable Community/operations boundary smoke passed with ${browserExecutable}.`);
  console.log("Direct #community retired to Home with no consumer Community navigation or route DOM.");
  console.log("Operations diagnostics stayed hidden without ?developer=1 and rendered only under entitled Settings.");
} catch (error) {
  console.error(`FAIL: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
} finally {
  if (server && server.exitCode === null) {
    server.kill();
    await new Promise((resolveWait) => {
      const timer = setTimeout(() => {
        if (server.exitCode === null) server.kill("SIGKILL");
        resolveWait();
      }, 2_000);
      server.once("exit", () => {
        clearTimeout(timer);
        resolveWait();
      });
    });
  }
  for (const profile of browserProfiles) rmSync(profile, { recursive: true, force: true });
  rmSync(dataDir, { recursive: true, force: true });
}
