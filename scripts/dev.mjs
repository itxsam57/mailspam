import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { loadEnvFile } from "node:process";

// npm exposes the JavaScript entry point that launched this lifecycle script.
// Capture it before loading project-local configuration so .env.local can never
// redirect the process launcher. Running that CLI through the current Node
// executable avoids trying to execute npm.cmd directly on Windows.
const npmExecPath = process.env.npm_execpath?.trim();

const envFile = resolve(process.cwd(), ".env.local");
try {
  loadEnvFile(envFile);
} catch (error) {
  if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) {
    throw error;
  }
}

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
