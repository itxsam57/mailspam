import { constants, closeSync, fstatSync, openSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { createSignedUpdate, SIGNED_UPDATE_FILE } from "./release-lifecycle-lib.mjs";
import { portablePackageName, RELEASE_MANIFEST_FILE, writeNormalizedText } from "./portable-package-lib.mjs";

function readPrivateKey(path) {
  const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
  const descriptor = openSync(path, flags);
  try {
    const state = fstatSync(descriptor);
    if (!state.isFile() || state.size < 80 || state.size > 16_384) throw new Error("Release signing key must be a bounded regular file.");
    if (process.platform !== "win32" && (state.mode & 0o077) !== 0) {
      throw new Error("Release signing key permissions must be owner-only.");
    }
    return readFileSync(descriptor, "utf8");
  } finally {
    closeSync(descriptor);
  }
}

const root = process.cwd();
const keyPath = process.env.EMAIL_SHIELD_RELEASE_SIGNING_KEY_FILE?.trim();
if (!keyPath) throw new Error("Set EMAIL_SHIELD_RELEASE_SIGNING_KEY_FILE to an owner-only Ed25519 private-key file.");
const packageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const packageRoot = resolve(root, "artifacts/release", portablePackageName(packageJson.version));
const manifestPath = join(packageRoot, RELEASE_MANIFEST_FILE);
const portableManifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const envelope = createSignedUpdate(portableManifest, readPrivateKey(resolve(keyPath)));
const expectedKeyId = process.env.EMAIL_SHIELD_RELEASE_SIGNING_KEY_ID?.trim();
if (expectedKeyId && expectedKeyId !== envelope.signature.keyId) throw new Error("Release signing key does not match the expected key ID.");
const output = resolve(process.env.EMAIL_SHIELD_SIGNED_UPDATE_OUTPUT?.trim() || join(dirname(packageRoot), `${portablePackageName(packageJson.version)}.${SIGNED_UPDATE_FILE}`));
writeNormalizedText(output, `${JSON.stringify(envelope, null, 2)}\n`);
process.stdout.write(`${JSON.stringify({ signedUpdate: output, version: envelope.manifest.version, releaseId: envelope.manifest.releaseId, keyId: envelope.signature.keyId })}\n`);
