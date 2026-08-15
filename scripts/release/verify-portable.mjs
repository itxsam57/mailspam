import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import {
  assertManifestShape,
  launcherContent,
  launcherRelativePath,
  listPackageFiles,
  MAX_PORTABLE_PACKAGE_BYTES,
  portablePackageName,
  publicOAuthClientIds,
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

const oauthClientIds = publicOAuthClientIds();
const googleClientSecret = String(process.env.EMAIL_SHIELD_GOOGLE_CLIENT_SECRET ?? "").trim();
const expectedGoogleLiveCapability = Boolean(oauthClientIds.google && googleClientSecret);
if (process.env.EMAIL_SHIELD_REQUIRE_LIVE_OAUTH === "1" && !expectedGoogleLiveCapability) {
  throw new Error("Live Google OAuth verification requires the matching desktop client ID and client secret.");
}
const actualLauncher = readFileSync(join(packageRoot, manifest.launcher), "utf8");
const expectedLauncher = launcherContent(process.platform, oauthClientIds);
if (actualLauncher !== expectedLauncher) {
  throw new Error("Portable package launcher does not contain the verified release OAuth application IDs.");
}
if (oauthClientIds.google && !actualLauncher.includes(oauthClientIds.google)) {
  throw new Error("Portable package launcher is missing the product-owned Google OAuth client ID.");
}
if (!oauthClientIds.microsoft && actualLauncher.includes("EMAIL_SHIELD_MICROSOFT_CLIENT_ID=")) {
  throw new Error("Portable package must not advertise an unconfigured Microsoft OAuth application ID.");
}
// Application secrets are deliberately not written into the portable launcher.
if (actualLauncher.includes("EMAIL_SHIELD_GOOGLE_CLIENT_SECRET=")) {
  throw new Error("Portable package launcher must not embed the Google client secret.");
}

const actualFiles = listPackageFiles(packageRoot, new Set([RELEASE_MANIFEST_FILE]));
if (JSON.stringify(actualFiles) !== JSON.stringify(manifest.files)) throw new Error("Portable package file inventory or digest verification failed.");
for (const requiredTool of ["tools/release-cli.mjs", "tools/release-lifecycle-lib.mjs", "tools/portable-package-lib.mjs"]) {
  if (!actualFiles.some((entry) => entry.path === requiredTool)) throw new Error(`Portable package is missing release lifecycle tool: ${requiredTool}`);
}

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
      EMAIL_SHIELD_GOOGLE_CLIENT_ID: oauthClientIds.google,
      ...(googleClientSecret ? { EMAIL_SHIELD_GOOGLE_CLIENT_SECRET: googleClientSecret } : {}),
      ...(oauthClientIds.microsoft ? { EMAIL_SHIELD_MICROSOFT_CLIENT_ID: oauthClientIds.microsoft } : {}),
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

  const csrf = html.match(/<meta name="email-shield-csrf" content="([^"]+)"/)?.[1] ?? "";
  const cookie = response.headers.get("set-cookie")?.split(";", 1)[0] ?? "";
  if (!csrf || !cookie.startsWith("email_shield_local_session=")) {
    throw new Error("Portable package smoke could not establish its protected dashboard session.");
  }
  const origin = `http://${host}:${port}`;
  const protectedHeaders = {
    Cookie: cookie,
    Origin: origin,
    "x-email-shield-csrf": csrf,
  };
  const googleConfigResponse = await fetch(`${origin}/api/accounts/oauth/google/config`, {
    headers: protectedHeaders,
    signal: AbortSignal.timeout(5_000),
  });
  const googleConfig = await googleConfigResponse.json().catch(() => ({}));
  if (!googleConfigResponse.ok || googleConfig.configured !== expectedGoogleLiveCapability) {
    throw new Error("Portable package Google OAuth capability did not match the runtime client-credential configuration.");
  }
  const microsoftConfigResponse = await fetch(`${origin}/api/accounts/oauth/microsoft/config`, {
    headers: protectedHeaders,
    signal: AbortSignal.timeout(5_000),
  });
  const microsoftConfig = await microsoftConfigResponse.json().catch(() => ({}));
  if (!microsoftConfigResponse.ok || microsoftConfig.configured !== Boolean(oauthClientIds.microsoft)) {
    throw new Error("Portable package Microsoft OAuth capability did not match the release configuration.");
  }
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
console.log(
  `Release OAuth application IDs: Google ${oauthClientIds.google ? "present" : "absent"}; `
  + `Microsoft ${oauthClientIds.microsoft ? "present" : "absent"}. `
  + `Google live capability in this verification environment: ${expectedGoogleLiveCapability ? "enabled" : "disabled"}.`,
);
console.log(`Release ID: ${manifest.releaseId}; files: ${manifest.files.length}; artifact bytes: ${manifest.artifactBytes}.`);
