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
  publicOAuthClientIds,
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

const oauthClientIds = publicOAuthClientIds();
if (process.env.EMAIL_SHIELD_REQUIRE_LIVE_OAUTH === "1" && !oauthClientIds.google) {
  throw new Error(
    "Consumer release packaging requires the product-owned Google desktop OAuth client ID. "
    + "OAuth providers without an application ID must remain unavailable in the consumer UI.",
  );
}

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
  "fixtures/scam-corpus/manifest.json",
  "scripts/release/release-cli.mjs",
  "scripts/release/release-lifecycle-lib.mjs",
  "scripts/release/portable-package-lib.mjs",
  "PRIVACY.md",
  "SECURITY.md",
  "THREAT_MODEL.md",
  "INCIDENT_RESPONSE.md",
  "docs/DEPLOYMENT_CAPACITY_COST.md",
  "docs/THREE_MILESTONE_FINAL_RECONCILIATION.md",
];
for (const path of requiredSources) {
  try { readFileSync(resolve(root, path)); }
  catch { throw new Error(`Portable package requires a completed production build: ${path}`); }
}

copyTree(resolve(root, "server/dist"), join(packageRoot, "app/server/dist"));
copyRegularFile(resolve(root, "server/package.json"), join(packageRoot, "app/server/package.json"));
copyRegularFile(resolve(root, "package-lock.json"), join(packageRoot, "app/package-lock.json"));
copyTree(resolve(root, "web"), join(packageRoot, "app/web"));
// Fixture mode is a supported consumer/owner acceptance path in the shipped
// application. The compiled fixture adapter resolves this corpus relative to
// app/server/dist, so the runtime asset must be part of the release package,
// not merely present in a source checkout.
copyTree(resolve(root, "fixtures/scam-corpus"), join(packageRoot, "app/fixtures/scam-corpus"));
copyRegularFile(resolve(root, "scripts/release/release-cli.mjs"), join(packageRoot, "tools/release-cli.mjs"), true);
copyRegularFile(resolve(root, "scripts/release/release-lifecycle-lib.mjs"), join(packageRoot, "tools/release-lifecycle-lib.mjs"));
copyRegularFile(resolve(root, "scripts/release/portable-package-lib.mjs"), join(packageRoot, "tools/portable-package-lib.mjs"));
for (const path of [
  "PRIVACY.md",
  "SECURITY.md",
  "THREAT_MODEL.md",
  "INCIDENT_RESPONSE.md",
  "docs/DEPLOYMENT_CAPACITY_COST.md",
  "docs/THREE_MILESTONE_FINAL_RECONCILIATION.md",
]) copyRegularFile(resolve(root, path), join(packageRoot, "docs", path.replace(/^docs\//, "")));

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
writeNormalizedText(
  join(packageRoot, launcherRelativePath()),
  launcherContent(process.platform, oauthClientIds),
  process.platform !== "win32",
);

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
console.log(
  `Live OAuth: Google ${oauthClientIds.google ? "configured" : "not configured"}; `
  + `Microsoft ${oauthClientIds.microsoft ? "configured" : "unavailable in this release"}.`,
);
console.log(`Files: ${manifest.files.length}; production packages: ${productionPackages.length}; artifact bytes: ${manifest.artifactBytes}.`);
