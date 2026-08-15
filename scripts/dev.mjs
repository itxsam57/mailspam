import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { loadEnvFile } from "node:process";

const envFile = resolve(process.cwd(), ".env.local");
try {
  loadEnvFile(envFile);
} catch (error) {
  if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) {
    throw error;
  }
}

const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const child = spawn(npm, ["run", "dev", "-w", "server"], {
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
