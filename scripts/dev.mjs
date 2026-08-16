import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseEnv } from "node:util";
import { enforceDevelopmentEntitlementBoundary } from "./development-entitlement-boundary.mjs";

const FIXTURE_LAUNCH_ARG = "--email-shield-fixtures";
const dedicatedFixtureLaunch = process.argv.includes(FIXTURE_LAUNCH_ARG);

// npm exposes the JavaScript entry point that launched this lifecycle script.
// Capture it before loading project-local configuration so .env.local can never
// redirect the process launcher. Running that CLI through the current Node
// executable avoids trying to execute npm.cmd directly on Windows.
const npmExecPath = process.env.npm_execpath?.trim();

// Source/owner acceptance deliberately treats the repository-local .env.local
// as the authoritative configuration layer for ordinary product configuration.
// Development entitlement is deliberately excluded from that authority below:
// it is an explicit launcher capability, not a sticky project setting.
const envFile = resolve(process.cwd(), ".env.local");
let envLocalLoaded = false;
try {
  const localEnvironment = parseEnv(readFileSync(envFile, "utf8"));
  for (const [key, value] of Object.entries(localEnvironment)) {
    process.env[key] = value;
  }
  envLocalLoaded = true;
} catch (error) {
  if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) {
    throw error;
  }
}

// Apply after .env.local. Normal source startup always strips stale development
// entitlement; only the dedicated fixture launcher argument can enable it.
enforceDevelopmentEntitlementBoundary(process.env, dedicatedFixtureLaunch);

// Source/browser acceptance is diagnostic mode. Enable the privacy-safe local
// workflow trace automatically unless the owner explicitly disables it in
// .env.local with EMAIL_SHIELD_RUNTIME_TRACE=0.
if (process.env.EMAIL_SHIELD_RUNTIME_TRACE === undefined) {
  process.env.EMAIL_SHIELD_RUNTIME_TRACE = "1";
}

const googleClientIdLoaded = Boolean(process.env.EMAIL_SHIELD_GOOGLE_CLIENT_ID?.trim());
const googleClientSecretLoaded = Boolean(process.env.EMAIL_SHIELD_GOOGLE_CLIENT_SECRET?.trim());
const runtimeTraceEnabled = process.env.EMAIL_SHIELD_RUNTIME_TRACE === "1";
console.log(
  `Email Shield source configuration: .env.local ${envLocalLoaded ? "loaded" : "not found"}; `
  + `Google client ID ${googleClientIdLoaded ? "loaded" : "missing"}; `
  + `Google client secret ${googleClientSecretLoaded ? "loaded" : "missing"}; `
  + `runtime workflow trace ${runtimeTraceEnabled ? "enabled" : "disabled"}; `
  + `development entitlement ${dedicatedFixtureLaunch ? "dedicated fixture launcher" : "disabled"}.`,
);

let command;
let args;
if (npmExecPath) {
  command = process.execPath;
  args = [npmExecPath, "run", "dev", "-w", "server"];
} else if (process.platform === "win32") {
  command = process.env.ComSpec?.trim() || "cmd.exe";
  args = ["/d", "/s", "/c", "npm run dev -w server"];
} else {
  command = "npm";
  args = ["run", "dev", "-w", "server"];
}

const child = spawn(command, args, {
  stdio: "inherit",
  env: process.env,
  windowsHide: true,
});

child.once("error", (error) => {
  console.error(`Could not start Email Shield source development server: ${error.message}`);
  process.exitCode = 1;
});
child.once("exit", (code, signal) => {
  if (signal) {
    console.error(`Email Shield source development server stopped by ${signal}.`);
    process.exitCode = 1;
    return;
  }
  process.exitCode = code ?? 1;
});
