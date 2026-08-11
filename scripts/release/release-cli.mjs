#!/usr/bin/env node
import {
  installRelease,
  readInstallState,
  repairReleaseActivation,
  rollbackRelease,
  uninstallRelease,
  updateRelease,
  verifyReleaseBundle,
} from "./release-lifecycle-lib.mjs";

function parseArguments(values) {
  const command = values[0];
  if (!command || !["verify", "install", "update", "status", "rollback", "repair", "uninstall"].includes(command)) {
    throw new Error("Usage: release-cli.mjs <verify|install|update|status|rollback|repair|uninstall> [options]");
  }
  const options = {};
  for (let index = 1; index < values.length; index++) {
    const name = values[index];
    if (!/^--[a-z-]+$/.test(name)) throw new Error(`Unknown release option: ${name}`);
    if (name === "--purge-data") {
      if (options.purgeData) throw new Error("Release options may not be repeated.");
      options.purgeData = true;
      continue;
    }
    const value = values[++index];
    if (!value || value.startsWith("--") || Object.hasOwn(options, name.slice(2))) {
      throw new Error(`Release option requires one non-repeated value: ${name}`);
    }
    options[name.slice(2)] = value;
  }
  return { command, options };
}

function exactOptions(options, required, optional = []) {
  const allowed = new Set([...required, ...optional]);
  const names = Object.keys(options);
  if (names.some((name) => !allowed.has(name)) || required.some((name) => !Object.hasOwn(options, name))) {
    throw new Error(`Required release options: ${required.map((name) => `--${name}`).join(", ") || "none"}.`);
  }
}

const { command, options } = parseArguments(process.argv.slice(2));
let result;
switch (command) {
  case "verify":
    exactOptions(options, ["package-root", "signed-update", "trust-store"]);
    result = verifyReleaseBundle({
      packageRoot: options["package-root"],
      signedUpdatePath: options["signed-update"],
      trustStorePath: options["trust-store"],
    }).release;
    break;
  case "install":
    exactOptions(options, ["package-root", "signed-update", "trust-store", "install-root"]);
    result = installRelease({
      packageRoot: options["package-root"],
      signedUpdatePath: options["signed-update"],
      trustStorePath: options["trust-store"],
      installRoot: options["install-root"],
    });
    break;
  case "update":
    exactOptions(options, ["package-root", "signed-update", "install-root"]);
    result = updateRelease({
      packageRoot: options["package-root"],
      signedUpdatePath: options["signed-update"],
      installRoot: options["install-root"],
    });
    break;
  case "status":
    exactOptions(options, ["install-root"]);
    result = readInstallState(options["install-root"]);
    break;
  case "rollback":
    exactOptions(options, ["install-root"]);
    result = rollbackRelease({ installRoot: options["install-root"] });
    break;
  case "repair":
    exactOptions(options, ["install-root"]);
    result = repairReleaseActivation({ installRoot: options["install-root"] });
    break;
  case "uninstall":
    exactOptions(options, ["install-root"], ["purgeData", "data-root"]);
    if (Boolean(options.purgeData) !== Boolean(options["data-root"])) {
      throw new Error("Data purge requires both --purge-data and --data-root.");
    }
    result = uninstallRelease({
      installRoot: options["install-root"],
      dataRoot: options["data-root"] ?? null,
      purgeData: Boolean(options.purgeData),
    });
    break;
}

process.stdout.write(`${JSON.stringify({ ok: true, command, result })}\n`);
