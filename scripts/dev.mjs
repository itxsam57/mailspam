import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseEnv } from "node:util";

// npm exposes the JavaScript entry point that launched this lifecycle script.
// Capture it before loading project-local configuration so .env.local can never
// redirect the process launcher. Running that CLI through the current Node
// executable avoids trying to execute npm.cmd directly on Windows.
const npmExecPath = process.env.npm_execpath?.trim();

// Source/owner acceptance deliberately treats the repository-local .env.local
// as the authoritative configuration layer. Node's built-in --env-file/loadEnvFile
// behavior gives an already-existing machine environment variable precedence,
// which can silently retain an old OAuth value and make the browser report that
// Google is unavailable even though .env.local was corrected. Parse the local
// file and apply its values explicitly so the file the owner is editing is the
// configuration the spawned Email Shield server actually receives.
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

const googleClientIdLoaded = Boolean(process.env.EMAIL_SHIELD_GOOGLE_CLIENT_ID?.trim());
const googleClientSecretLoaded = Boolean(process.env.EMAIL_SHIELD_GOOGLE_CLIENT_SECRET?.trim());
console.log(
  `Email Shield source configuration: .env.local ${envLocalLoaded ? "loaded" : "not found"}; `
  + `Google client ID ${googleClientIdLoaded ? "loaded" : "missing"}; `
  + `Google client secret ${googleClientSecretLoaded ? "loaded" : "missing"}.`,
);

let command;
let args;
if (npmExecPath) {
  command = process.execPath;
  args = [npmExecPath, "run", "dev", "-w", "server"];
} else if (process.platform === "win32") {
  // Direct `node scripts/dev.mjs` remains supported on Windows. .cmd files must
  // be invoked through the Windows command processor rather than spawn()ed as
  // standalone executables.
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
