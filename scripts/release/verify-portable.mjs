import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  assertManifestShape,
  launcherRelativePath,
  listPackageFiles,
  MAX_PORTABLE_PACKAGE_BYTES,
  portablePackageName,
  RELEASE_MANIFEST_FILE,
  runtimeRelativePath,
} from "./portable-package-lib.mjs";

const root = process.cwd();
const packageJson = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));
const packageRoot = resolve(root, "artifacts/release", portablePackageName(packageJson.version));
const manifest = JSON.parse(readFileSync(join(packageRoot, RELEASE_MANIFEST_FILE), "utf8"));
assertManifestShape(manifest);
if (manifest.platform !== process.platform || manifest.architecture !== process.arch) throw new Error("Portable package target does not match the verification host.");
if (manifest.nodeVersion !== process.versions.node) throw new Error("Portable package Node version does not match the verified build runtime.");
if (manifest.launcher !== launcherRelativePath() || manifest.entrypoint !== "app/server/dist/index.js") throw new Error("Portable package entrypoint or launcher is invalid.");
if (manifest.productionPackages.includes("googleapis")) throw new Error("Portable package contains the broad generated Google API catalog.");

const actualFiles = listPackageFiles(packageRoot, new Set([RELEASE_MANIFEST_FILE]));
if (JSON.stringify(actualFiles) !== JSON.stringify(manifest.files)) throw new Error("Portable package file inventory or digest verification failed.");
for (const requiredTool of ["tools/release-cli.mjs", "tools/release-lifecycle-lib.mjs", "tools/portable-package-lib.mjs"]) {
  if (!actualFiles.some((entry) => entry.path === requiredTool)) throw new Error(`Portable package is missing release lifecycle tool: ${requiredTool}`);
}

// The shipped Fixture-mode adapters are an intentional product acceptance path,
// not a source-tree-only test helper. Verify both the corpus manifest and every
// file it names, so a package cannot pass integrity verification while still
// being unusable by consumers in Fixture mode.
const fixtureManifestPath = join(packageRoot, "app/fixtures/scam-corpus/manifest.json");
let fixtureManifest;
try {
  fixtureManifest = JSON.parse(readFileSync(fixtureManifestPath, "utf8"));
} catch (error) {
  throw new Error(`Portable package is missing or has an invalid Fixture corpus manifest: ${error instanceof Error ? error.message : String(error)}`);
}
if (!Array.isArray(fixtureManifest) || fixtureManifest.length === 0) {
  throw new Error("Portable package Fixture corpus manifest must contain at least one message.");
}
const packagePaths = new Set(actualFiles.map((entry) => entry.path));
for (const entry of fixtureManifest) {
  if (!entry || typeof entry !== "object" || typeof entry.file !== "string" || !/^[A-Za-z0-9._/-]+$/.test(entry.file) || entry.file.includes("..")) {
    throw new Error("Portable package Fixture corpus manifest contains an unsafe or invalid file entry.");
  }
  const requiredPath = `app/fixtures/scam-corpus/${entry.file}`;
  if (!packagePaths.has(requiredPath)) throw new Error(`Portable package is missing Fixture corpus message: ${requiredPath}`);
}

const actualArtifactBytes = actualFiles.reduce((total, file) => total + file.bytes, 0);
if (actualArtifactBytes !== manifest.artifactBytes || actualArtifactBytes > MAX_PORTABLE_PACKAGE_BYTES) {
  throw new Error("Portable package size verification failed.");
}
const forbidden = actualFiles.filter((entry) =>
  /(^|\/)(?:\.env(?:\..*)?|personal-policies\.enc\.json|scan-state\.enc\.json|relationship-history\.enc\.json|background-protection\.enc\.json|community-feed-rollback\.enc\.json|community-.*\.(?:key|pem)|release-(?:private|signing).*\.(?:key|pem)|credentials?\.json|tokens?\.json)$/i.test(entry.path),
);
if (forbidden.length) throw new Error(`Portable package contains forbidden state/secret paths: ${forbidden.map((entry) => entry.path).join(", ")}`);
if (actualFiles.some((entry) => /node_modules\/(?:vitest|typescript|tsx|@types)(?:\/|$)/.test(entry.path))) {
  throw new Error("Portable package contains development-only dependencies.");
}

const runtime = join(packageRoot, runtimeRelativePath());
const version = await new Promise((resolveVersion, reject) => {
  const child = spawn(runtime, ["--version"], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.once("error", reject);
  child.once("exit", (code) => code === 0 ? resolveVersion(stdout.trim()) : reject(new Error(`Bundled runtime failed: ${stderr.trim()}`)));
});
if (version !== `v${manifest.nodeVersion}`) throw new Error(`Bundled runtime version mismatch: ${version}`);

const host = "127.0.0.1";
const port = await new Promise((resolvePort, reject) => {
  const server = net.createServer();
  server.once("error", reject);
  server.listen(0, host, () => {
    const address = server.address();
    const value = typeof address === "object" && address ? address.port : null;
    server.close((error) => error ? reject(error) : resolvePort(value));
  });
});
if (!Number.isInteger(port)) throw new Error("Could not reserve a portable-package smoke port.");

const dataDirectory = mkdtempSync(join(tmpdir(), "email-shield-portable-smoke-"));
let child;
let stderr = "";
try {
  child = spawn(runtime, [join(packageRoot, manifest.entrypoint)], {
    cwd: packageRoot,
    env: {
      ...process.env,
      HOST: host,
      PORT: String(port),
      EMAIL_SHIELD_DATA_DIR: dataDirectory,
      XDG_DATA_HOME: dataDirectory,
    },
    stdio: ["ignore", "ignore", "pipe"],
    windowsHide: true,
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const deadline = Date.now() + 20_000;
  let response = null;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`Portable package exited before smoke readiness with code ${child.exitCode}: ${stderr}`);
    try {
      response = await fetch(`http://${host}:${port}/`, { signal: AbortSignal.timeout(1_000) });
      if (response.ok) break;
    } catch {}
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  if (!response?.ok) throw new Error(`Portable package did not become ready: ${stderr}`);
  const html = await response.text();
  if (!html.includes("Email Shield")) throw new Error("Portable package served an unexpected dashboard.");
} finally {
  if (child && child.exitCode === null) {
    child.kill();
    await new Promise((resolveWait) => {
      const timer = setTimeout(() => { if (child.exitCode === null) child.kill("SIGKILL"); resolveWait(); }, 2_000);
      child.once("exit", () => { clearTimeout(timer); resolveWait(); });
    });
  }
  rmSync(dataDirectory, { recursive: true, force: true });
}

console.log(`Portable package verified: ${packageRoot}`);
console.log(`Release ID: ${manifest.releaseId}; files: ${manifest.files.length}; artifact bytes: ${manifest.artifactBytes}.`);
