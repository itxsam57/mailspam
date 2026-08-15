import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const root = process.cwd();
const smokeScript = resolve(root, "scripts/engineering/smoke-browser-boot.mjs");
const MAX_BROWSER_BOOT_ATTEMPTS = 2;
const RETRYABLE_BROWSER_STARTUP_FAILURES = [
  "Timed out waiting for Chromium to publish its authoritative DevTools port",
  "Chromium exited before publishing DevToolsActivePort",
];

function runBrowserBootAttempt() {
  return spawnSync(process.execPath, [smokeScript], {
    cwd: root,
    env: process.env,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
}

function combinedOutput(result) {
  return `${result.stdout ?? ""}${result.stderr ?? ""}`;
}

function replay(result) {
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
}

function retryableStartupFailure(result) {
  if (result.status === 0) return false;
  const output = combinedOutput(result);
  return RETRYABLE_BROWSER_STARTUP_FAILURES.some((message) => output.includes(message));
}

let lastResult = null;
for (let attempt = 1; attempt <= MAX_BROWSER_BOOT_ATTEMPTS; attempt += 1) {
  const result = runBrowserBootAttempt();
  lastResult = result;
  if (result.error) {
    replay(result);
    throw result.error;
  }
  if (result.status === 0) {
    replay(result);
    process.exit(0);
  }

  if (!retryableStartupFailure(result) || attempt === MAX_BROWSER_BOOT_ATTEMPTS) {
    replay(result);
    process.exit(typeof result.status === "number" ? result.status : 1);
  }

  replay(result);
  console.warn(`Browser boot smoke attempt ${attempt} hit an isolated Chromium startup failure. Relaunching once from a fresh profile.`);
}

replay(lastResult ?? {});
process.exit(typeof lastResult?.status === "number" ? lastResult.status : 1);
