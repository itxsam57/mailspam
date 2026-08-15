import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { execFileSync } from "node:child_process";

export const PORTABLE_MANIFEST_SCHEMA = 1;
export const MAX_PORTABLE_PACKAGE_BYTES = 256 * 1024 * 1024;
export const NORMALIZED_MTIME = new Date("2000-01-01T00:00:00.000Z");
export const RELEASE_MANIFEST_FILE = "release-manifest.json";
const lexicalCompare = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const GOOGLE_DESKTOP_CLIENT_ID = /^\d+-[A-Za-z0-9_-]+\.apps\.googleusercontent\.com$/;
const MICROSOFT_PUBLIC_CLIENT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function publicOAuthClientIds(environment = process.env) {
  const google = String(environment.EMAIL_SHIELD_GOOGLE_CLIENT_ID ?? "").trim();
  const microsoft = String(environment.EMAIL_SHIELD_MICROSOFT_CLIENT_ID ?? "").trim();
  if (google && !GOOGLE_DESKTOP_CLIENT_ID.test(google)) {
    throw new Error("EMAIL_SHIELD_GOOGLE_CLIENT_ID is not a valid Google desktop OAuth client ID.");
  }
  if (microsoft && !MICROSOFT_PUBLIC_CLIENT_ID.test(microsoft)) {
    throw new Error("EMAIL_SHIELD_MICROSOFT_CLIENT_ID is not a valid Microsoft application client ID.");
  }
  return { google, microsoft };
}

export function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

export function normalizeRelativePath(path) {
  return path.split(sep).join("/");
}

function normalizedMode(sourceMode, executable = false) {
  return executable || (sourceMode & 0o111) !== 0 ? 0o755 : 0o644;
}

function finalizeFile(path, mode) {
  chmodSync(path, mode);
  utimesSync(path, NORMALIZED_MTIME, NORMALIZED_MTIME);
}

export function copyRegularFile(source, destination, executable = false) {
  const sourceState = lstatSync(source);
  if (!sourceState.isFile() || sourceState.isSymbolicLink()) {
    throw new Error(`Portable package source must be a regular file: ${source}`);
  }
  mkdirSync(dirname(destination), { recursive: true });
  copyFileSync(source, destination);
  finalizeFile(destination, normalizedMode(sourceState.mode, executable));
}

export function copyTree(source, destination) {
  const sourceState = lstatSync(source);
  if (sourceState.isSymbolicLink()) throw new Error(`Portable package sources must not contain symlinks: ${source}`);
  if (sourceState.isFile()) {
    copyRegularFile(source, destination);
    return;
  }
  if (!sourceState.isDirectory()) throw new Error(`Unsupported portable package source type: ${source}`);
  mkdirSync(destination, { recursive: true });
  for (const entry of readdirSync(source, { withFileTypes: true }).sort((a, b) => lexicalCompare(a.name, b.name))) {
    // Dependency packages are copied from the lockfile one package at a time;
    // recursively copying nested node_modules would reintroduce dev-only code.
    if (entry.name === "node_modules") continue;
    copyTree(join(source, entry.name), join(destination, entry.name));
  }
  chmodSync(destination, 0o755);
  utimesSync(destination, NORMALIZED_MTIME, NORMALIZED_MTIME);
}

export function productionPackagePaths(lockfile) {
  const packages = Object.entries(lockfile.packages ?? {})
    .filter(([path, metadata]) => path.startsWith("node_modules/") && metadata?.dev !== true && metadata?.link !== true)
    .map(([path, metadata]) => ({ path, optional: metadata?.optional === true }))
    .sort((left, right) => lexicalCompare(left.path, right.path));
  if (packages.length === 0) throw new Error("The lockfile did not contain a production dependency closure.");
  return packages;
}

export function listPackageFiles(root, excluded = new Set()) {
  const files = [];
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => lexicalCompare(a.name, b.name))) {
      const absolute = join(directory, entry.name);
      const relativePath = normalizeRelativePath(relative(root, absolute));
      if (excluded.has(relativePath)) continue;
      const state = lstatSync(absolute);
      if (state.isSymbolicLink()) throw new Error(`Portable package must not contain symlinks: ${relativePath}`);
      if (state.isDirectory()) visit(absolute);
      else if (state.isFile()) files.push({
        path: relativePath,
        bytes: state.size,
        sha256: sha256File(absolute),
        mode: (state.mode & 0o111) !== 0 ? "755" : "644",
      });
      else throw new Error(`Portable package contains an unsupported filesystem entry: ${relativePath}`);
    }
  };
  visit(root);
  return files;
}

export function canonicalManifestPayload(manifest) {
  return JSON.stringify({
    schemaVersion: manifest.schemaVersion,
    product: manifest.product,
    version: manifest.version,
    commit: manifest.commit,
    platform: manifest.platform,
    architecture: manifest.architecture,
    nodeVersion: manifest.nodeVersion,
    entrypoint: manifest.entrypoint,
    launcher: manifest.launcher,
    artifactBytes: manifest.artifactBytes,
    productionPackages: manifest.productionPackages,
    files: manifest.files,
  });
}

export function releaseId(manifest) {
  return createHash("sha256").update(canonicalManifestPayload(manifest), "utf8").digest("hex");
}

export function writeNormalizedText(path, content, executable = false) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content, { encoding: "utf8", mode: executable ? 0o755 : 0o644 });
  finalizeFile(path, executable ? 0o755 : 0o644);
}

export function gitValue(root, args) {
  return execFileSync("git", args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

export function assertCleanReleaseTree(root) {
  if (process.env.EMAIL_SHIELD_ALLOW_DIRTY_PACKAGE === "1") return;
  const status = gitValue(root, ["status", "--porcelain"]);
  if (status) throw new Error("Portable release packaging requires a clean git worktree.");
}

export function safeReplaceOutput(releaseRoot, packageRoot) {
  const resolvedReleaseRoot = resolve(releaseRoot);
  const resolvedPackageRoot = resolve(packageRoot);
  if (resolvedPackageRoot === resolvedReleaseRoot || !resolvedPackageRoot.startsWith(`${resolvedReleaseRoot}${sep}`)) {
    throw new Error("Refusing to replace an output path outside the release artifact directory.");
  }
  if (existsSync(resolvedPackageRoot)) rmSync(resolvedPackageRoot, { recursive: true, force: true });
  mkdirSync(resolvedPackageRoot, { recursive: true });
}

export function portablePackageName(productVersion, platform = process.platform, architecture = process.arch) {
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(productVersion)) throw new Error("Product version is not release-safe.");
  if (!/^[a-z0-9_-]+$/i.test(platform) || !/^[a-z0-9_-]+$/i.test(architecture)) {
    throw new Error("Platform or architecture is not release-safe.");
  }
  return `email-shield-${productVersion}-${platform}-${architecture}`;
}

export function runtimeRelativePath(platform = process.platform) {
  return platform === "win32" ? "runtime/node.exe" : "runtime/node";
}

export function launcherRelativePath(platform = process.platform) {
  return platform === "win32" ? "EmailShield.cmd" : "email-shield";
}

export function launcherContent(platform = process.platform, oauthClientIds = publicOAuthClientIds()) {
  const { google, microsoft } = publicOAuthClientIds({
    EMAIL_SHIELD_GOOGLE_CLIENT_ID: oauthClientIds?.google ?? "",
    EMAIL_SHIELD_MICROSOFT_CLIENT_ID: oauthClientIds?.microsoft ?? "",
  });
  if (platform === "win32") {
    const oauthLines = [
      google ? `set "EMAIL_SHIELD_GOOGLE_CLIENT_ID=${google}"\r\n` : "",
      microsoft ? `set "EMAIL_SHIELD_MICROSOFT_CLIENT_ID=${microsoft}"\r\n` : "",
    ].join("");
    return `@echo off\r\nsetlocal\r\nset "EMAIL_SHIELD_PACKAGE_ROOT=%~dp0"\r\n${oauthLines}"%EMAIL_SHIELD_PACKAGE_ROOT%runtime\\node.exe" "%EMAIL_SHIELD_PACKAGE_ROOT%app\\server\\dist\\index.js"\r\n`;
  }
  const oauthLines = [
    google ? `EMAIL_SHIELD_GOOGLE_CLIENT_ID='${google}'\nexport EMAIL_SHIELD_GOOGLE_CLIENT_ID\n` : "",
    microsoft ? `EMAIL_SHIELD_MICROSOFT_CLIENT_ID='${microsoft}'\nexport EMAIL_SHIELD_MICROSOFT_CLIENT_ID\n` : "",
  ].join("");
  return `#!/bin/sh\nset -eu\nEMAIL_SHIELD_PACKAGE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\n${oauthLines}exec "$EMAIL_SHIELD_PACKAGE_ROOT/runtime/node" "$EMAIL_SHIELD_PACKAGE_ROOT/app/server/dist/index.js"\n`;
}

export function assertManifestShape(manifest) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) throw new Error("Release manifest must be an object.");
  if (manifest.schemaVersion !== PORTABLE_MANIFEST_SCHEMA) throw new Error("Unsupported portable release manifest schema.");
  if (manifest.product !== "Email Shield") throw new Error("Portable release product identity is invalid.");
  if (!/^[a-f0-9]{40}$/.test(manifest.commit)) throw new Error("Portable release commit is invalid.");
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(manifest.version)) throw new Error("Portable release version is invalid.");
  if (!Array.isArray(manifest.productionPackages) || !Array.isArray(manifest.files)) throw new Error("Portable release manifest lists are invalid.");
  if (!Number.isSafeInteger(manifest.artifactBytes) || manifest.artifactBytes <= 0 || manifest.artifactBytes > MAX_PORTABLE_PACKAGE_BYTES) {
    throw new Error("Portable release artifact size is outside the accepted budget.");
  }
  if (!/^[a-f0-9]{64}$/.test(manifest.releaseId ?? "")) throw new Error("Portable release ID is invalid.");
  if (releaseId(manifest) !== manifest.releaseId) throw new Error("Portable release manifest ID does not match its canonical payload.");
}

export function packageRootFromManifestPath(manifestPath) {
  if (basename(manifestPath) !== RELEASE_MANIFEST_FILE) throw new Error("Unexpected portable manifest filename.");
  return dirname(manifestPath);
}
