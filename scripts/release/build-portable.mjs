import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  assertCleanReleaseTree,
  copyRegularFile,
  copyTree,
  gitValue,
  launcherContent,
  launcherRelativePath,
  listPackageFiles,
  portablePackageName,
  productionPackagePaths,
  releaseId,
  RELEASE_MANIFEST_FILE,
  runtimeRelativePath,
  safeReplaceOutput,
  writeNormalizedText,
} from "./portable-package-lib.mjs";

const root = process.cwd();
const packageJson = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));
const lockfile = JSON.parse(readFileSync(resolve(root, "package-lock.json"), "utf8"));
if (Number(process.versions.node.split(".")[0]) !== 22) {
  throw new Error(`Portable packages must embed Node.js 22; current runtime is ${process.versions.node}.`);
}
assertCleanReleaseTree(root);

const releaseRoot = resolve(root, "artifacts/release");
const packageName = portablePackageName(packageJson.version);
const packageRoot = join(releaseRoot, packageName);
safeReplaceOutput(releaseRoot, packageRoot);

const requiredSources = [
  "server/dist/index.js",
  "server/dist/workers/scanWorker.js",
  "server/package.json",
  "package-lock.json",
  "web/index.html",
];
for (const path of requiredSources) {
  try { readFileSync(resolve(root, path)); }
  catch { throw new Error(`Portable package requires a completed production build: ${path}`); }
}

copyTree(resolve(root, "server/dist"), join(packageRoot, "app/server/dist"));
copyRegularFile(resolve(root, "server/package.json"), join(packageRoot, "app/server/package.json"));
copyRegularFile(resolve(root, "package-lock.json"), join(packageRoot, "app/package-lock.json"));
copyTree(resolve(root, "web"), join(packageRoot, "app/web"));

const productionPackages = [];
for (const dependency of productionPackagePaths(lockfile)) {
  const source = resolve(root, dependency.path);
  try {
    copyTree(source, join(packageRoot, "app", dependency.path));
    productionPackages.push(dependency.path.slice("node_modules/".length));
  } catch (error) {
    if (dependency.optional && String(error).includes("ENOENT")) continue;
    throw error;
  }
}

copyRegularFile(process.execPath, join(packageRoot, runtimeRelativePath()), true);
writeNormalizedText(join(packageRoot, launcherRelativePath()), launcherContent(), process.platform !== "win32");

const manifest = {
  schemaVersion: 1,
  product: "Email Shield",
  version: packageJson.version,
  commit: gitValue(root, ["rev-parse", "HEAD"]),
  platform: process.platform,
  architecture: process.arch,
  nodeVersion: process.versions.node,
  entrypoint: "app/server/dist/index.js",
  launcher: launcherRelativePath(),
  productionPackages,
  files: listPackageFiles(packageRoot, new Set([RELEASE_MANIFEST_FILE])),
};
manifest.artifactBytes = manifest.files.reduce((total, file) => total + file.bytes, 0);
manifest.releaseId = releaseId(manifest);
writeNormalizedText(join(packageRoot, RELEASE_MANIFEST_FILE), `${JSON.stringify(manifest, null, 2)}\n`);

console.log(`Portable package built: ${packageRoot}`);
console.log(`Release ID: ${manifest.releaseId}`);
console.log(`Files: ${manifest.files.length}; production packages: ${productionPackages.length}; artifact bytes: ${manifest.artifactBytes}.`);
