import { readFileSync } from "node:fs";
import { join } from "node:path";

const TRANSIENT_PORT_FILE_ERRORS = new Set(["ENOENT", "EBUSY"]);

function isTransientPortFileError(error) {
  return Boolean(error && typeof error === "object" && TRANSIENT_PORT_FILE_ERRORS.has(error.code));
}

function parseDevToolsPort(contents) {
  const firstLine = String(contents ?? "").split(/\r?\n/, 1)[0]?.trim() ?? "";
  const port = Number.parseInt(firstLine, 10);
  return Number.isInteger(port) && port > 0 && port <= 65_535
    ? { port, firstLine }
    : { port: null, firstLine };
}

export async function waitForDevToolsPort(
  profileDirectory,
  processRef,
  stderr,
  timeoutMs = 20_000,
  dependencies = {},
) {
  const readPortFile = dependencies.readPortFile ?? readFileSync;
  const delay = dependencies.delay ?? ((ms) => new Promise((resolveWait) => setTimeout(resolveWait, ms)));
  const activePortPath = join(profileDirectory, "DevToolsActivePort");
  const deadline = Date.now() + timeoutMs;
  let lastError = null;

  while (Date.now() < deadline) {
    if (processRef?.exitCode !== null) {
      throw new Error(`Chromium exited before publishing DevToolsActivePort with code ${processRef.exitCode}.\n${stderr()}`);
    }

    try {
      const parsed = parseDevToolsPort(readPortFile(activePortPath, "utf8"));
      if (parsed.port !== null) return parsed.port;
      lastError = new Error(`Invalid DevToolsActivePort value: ${JSON.stringify(parsed.firstLine)}`);
    } catch (error) {
      if (!isTransientPortFileError(error)) throw error;
      lastError = error;
    }

    await delay(50);
  }

  const detail = lastError instanceof Error
    ? lastError.message
    : "DevToolsActivePort was not created";
  throw new Error(`Timed out waiting for Chromium to publish its authoritative DevTools port: ${detail}\n${stderr()}`);
}
