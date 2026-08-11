import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { createSignedUpdate, releaseKeyId } from "../release/release-lifecycle-lib.mjs";
import {
  portablePackageName,
  RELEASE_MANIFEST_FILE,
  runtimeRelativePath,
} from "../release/portable-package-lib.mjs";

const root = process.cwd();
const packageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const packageRoot = resolve(root, "artifacts/release", portablePackageName(packageJson.version));
const portableManifest = JSON.parse(readFileSync(join(packageRoot, RELEASE_MANIFEST_FILE), "utf8"));
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
const trustStore = {
  schemaVersion: 1,
  product: "Email Shield",
  keys: [{ keyId: releaseKeyId(publicKey), publicKeyPem }],
};
const envelope = createSignedUpdate(portableManifest, privateKey.export({ format: "pem", type: "pkcs8" }));
const temporary = mkdtempSync(join(tmpdir(), "email-shield-release-smoke-"));
const trustStorePath = join(temporary, "release-trust.json");
const signedUpdatePath = join(temporary, "signed-update.json");
const installRoot = join(temporary, "installed", "email-shield");
writeFileSync(trustStorePath, `${JSON.stringify(trustStore, null, 2)}\n`, { mode: 0o600 });
writeFileSync(signedUpdatePath, `${JSON.stringify(envelope, null, 2)}\n`, { mode: 0o600 });

const runtime = join(packageRoot, runtimeRelativePath());
const cli = join(packageRoot, "tools/release-cli.mjs");
function run(args) {
  const result = spawnSync(runtime, [cli, ...args], {
    cwd: packageRoot,
    encoding: "utf8",
    windowsHide: true,
    timeout: 120_000,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`Packaged release lifecycle failed: ${result.stderr || result.stdout}`);
  const output = JSON.parse(result.stdout.trim());
  if (output.ok !== true) throw new Error("Packaged release lifecycle returned an invalid result.");
  return output.result;
}

try {
  const verified = run(["verify", "--package-root", packageRoot, "--signed-update", signedUpdatePath, "--trust-store", trustStorePath]);
  if (verified.releaseId !== portableManifest.releaseId) throw new Error("Packaged release verification returned the wrong release.");
  const installed = run([
    "install", "--package-root", packageRoot, "--signed-update", signedUpdatePath,
    "--trust-store", trustStorePath, "--install-root", installRoot,
  ]);
  if (installed.activeReleaseId !== portableManifest.releaseId) throw new Error("Packaged installer activated the wrong release.");
  const status = run(["status", "--install-root", installRoot]);
  if (status.activeReleaseId !== portableManifest.releaseId) throw new Error("Packaged installer status is inconsistent.");
  const removed = run(["uninstall", "--install-root", installRoot]);
  if (!removed.programRemoved || removed.dataPurged) throw new Error("Packaged uninstall result is invalid.");
} finally {
  rmSync(temporary, { recursive: true, force: true });
}

console.log(`Compiled signed-release install/uninstall smoke passed for release ${portableManifest.releaseId}.`);
