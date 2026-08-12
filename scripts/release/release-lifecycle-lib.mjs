import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, parse, resolve, sep } from "node:path";
import { homedir } from "node:os";
import {
  assertManifestShape,
  listPackageFiles,
  RELEASE_MANIFEST_FILE,
  sha256File,
} from "./portable-package-lib.mjs";

export const SIGNED_UPDATE_SCHEMA = 1;
export const RELEASE_TRUST_SCHEMA = 1;
export const INSTALL_STATE_SCHEMA = 1;
export const SIGNED_UPDATE_FILE = "signed-update.json";
export const RELEASE_TRUST_FILE = "release-trust.json";
export const INSTALL_MARKER_FILE = ".email-shield-install.json";
export const DATA_MARKER_FILE = ".email-shield-data.json";
export const INSTALL_STATE_FILE = "install-state.json";
export const ACTIVE_RELEASE_FILE = "active-release";
export const MAX_SIGNED_UPDATE_BYTES = 64 * 1024;
export const MAX_RELEASE_TRUST_BYTES = 64 * 1024;
const MAX_TRUSTED_KEYS = 4;
const RELEASE_ID_PATTERN = /^[a-f0-9]{64}$/;
const VERSION_PATTERN = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const lexicalCompare = (left, right) => left < right ? -1 : left > right ? 1 : 0;

function exactFields(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} must be an object.`);
  const actual = Object.keys(value).sort(lexicalCompare);
  const wanted = [...expected].sort(lexicalCompare);
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) throw new Error(`${label} fields are invalid.`);
}

function boundedJson(path, maximumBytes, label) {
  const state = lstatSync(path);
  if (!state.isFile() || state.isSymbolicLink() || state.size <= 0 || state.size > maximumBytes) {
    throw new Error(`${label} is not a bounded regular file.`);
  }
  try { return JSON.parse(readFileSync(path, "utf8")); }
  catch { throw new Error(`${label} is not valid JSON.`); }
}

function normalizedPublicPem(value) {
  if (typeof value !== "string" || value.length < 80 || value.length > 8_192) throw new Error("Release public key is invalid.");
  const key = createPublicKey(value);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("Release keys must use Ed25519.");
  return key.export({ format: "pem", type: "spki" }).toString();
}

export function releaseKeyId(publicKey) {
  const key = publicKey && typeof publicKey === "object" && publicKey.type === "public"
    ? publicKey
    : createPublicKey(publicKey);
  if (key.asymmetricKeyType !== "ed25519") throw new Error("Release keys must use Ed25519.");
  return createHash("sha256").update(key.export({ format: "der", type: "spki" })).digest("hex");
}

export function assertReleaseTrustStore(value) {
  exactFields(value, ["schemaVersion", "product", "keys"], "Release trust store");
  if (value.schemaVersion !== RELEASE_TRUST_SCHEMA || value.product !== "Email Shield") {
    throw new Error("Release trust store identity is invalid.");
  }
  if (!Array.isArray(value.keys) || value.keys.length < 1 || value.keys.length > MAX_TRUSTED_KEYS) {
    throw new Error("Release trust store key count is invalid.");
  }
  const ids = new Set();
  for (const entry of value.keys) {
    exactFields(entry, ["keyId", "publicKeyPem"], "Release trust key");
    const pem = normalizedPublicPem(entry.publicKeyPem);
    const keyId = releaseKeyId(pem);
    if (entry.keyId !== keyId || ids.has(keyId)) throw new Error("Release trust key identity is invalid or duplicated.");
    ids.add(keyId);
  }
}

export function readReleaseTrustStore(path) {
  const value = boundedJson(path, MAX_RELEASE_TRUST_BYTES, "Release trust store");
  assertReleaseTrustStore(value);
  return value;
}

function assertReleaseManifest(value) {
  exactFields(value, [
    "schemaVersion", "product", "channel", "version", "commit", "platform", "architecture",
    "releaseId", "portableManifestSha256", "minimumUpdaterSchema",
  ], "Signed release manifest");
  if (value.schemaVersion !== SIGNED_UPDATE_SCHEMA || value.product !== "Email Shield" || value.channel !== "stable") {
    throw new Error("Signed release identity is invalid.");
  }
  if (!VERSION_PATTERN.test(value.version) || !/^[a-f0-9]{40}$/.test(value.commit)) {
    throw new Error("Signed release version or commit is invalid.");
  }
  if (!/^[a-z0-9_-]+$/i.test(value.platform) || !/^[a-z0-9_-]+$/i.test(value.architecture)) {
    throw new Error("Signed release target is invalid.");
  }
  if (!RELEASE_ID_PATTERN.test(value.releaseId) || !RELEASE_ID_PATTERN.test(value.portableManifestSha256)) {
    throw new Error("Signed release digest is invalid.");
  }
  if (value.minimumUpdaterSchema !== INSTALL_STATE_SCHEMA) throw new Error("Signed release requires an unsupported updater schema.");
}

export function canonicalReleasePayload(manifest) {
  assertReleaseManifest(manifest);
  return JSON.stringify({
    schemaVersion: manifest.schemaVersion,
    product: manifest.product,
    channel: manifest.channel,
    version: manifest.version,
    commit: manifest.commit,
    platform: manifest.platform,
    architecture: manifest.architecture,
    releaseId: manifest.releaseId,
    portableManifestSha256: manifest.portableManifestSha256,
    minimumUpdaterSchema: manifest.minimumUpdaterSchema,
  });
}

export function createSignedUpdate(portableManifest, privateKeyPem) {
  assertManifestShape(portableManifest);
  const privateKey = createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Release private key must use Ed25519.");
  const publicKey = createPublicKey(privateKey);
  const manifest = {
    schemaVersion: SIGNED_UPDATE_SCHEMA,
    product: "Email Shield",
    channel: "stable",
    version: portableManifest.version,
    commit: portableManifest.commit,
    platform: portableManifest.platform,
    architecture: portableManifest.architecture,
    releaseId: portableManifest.releaseId,
    portableManifestSha256: createHash("sha256").update(`${JSON.stringify(portableManifest, null, 2)}\n`, "utf8").digest("hex"),
    minimumUpdaterSchema: INSTALL_STATE_SCHEMA,
  };
  const signature = sign(null, Buffer.from(canonicalReleasePayload(manifest), "utf8"), privateKey).toString("base64");
  return {
    schemaVersion: SIGNED_UPDATE_SCHEMA,
    manifest,
    signature: {
      algorithm: "Ed25519",
      keyId: releaseKeyId(publicKey),
      value: signature,
    },
  };
}

export function verifySignedUpdate(value, trustStore) {
  assertReleaseTrustStore(trustStore);
  exactFields(value, ["schemaVersion", "manifest", "signature"], "Signed update envelope");
  if (value.schemaVersion !== SIGNED_UPDATE_SCHEMA) throw new Error("Signed update envelope schema is unsupported.");
  assertReleaseManifest(value.manifest);
  exactFields(value.signature, ["algorithm", "keyId", "value"], "Signed update signature");
  if (value.signature.algorithm !== "Ed25519" || !RELEASE_ID_PATTERN.test(value.signature.keyId)) {
    throw new Error("Signed update signature identity is invalid.");
  }
  if (typeof value.signature.value !== "string" || value.signature.value.length < 80 || value.signature.value.length > 128) {
    throw new Error("Signed update signature encoding is invalid.");
  }
  const bytes = Buffer.from(value.signature.value, "base64");
  if (bytes.length !== 64 || bytes.toString("base64") !== value.signature.value) throw new Error("Signed update signature is not canonical.");
  const trusted = trustStore.keys.find((entry) => entry.keyId === value.signature.keyId);
  if (!trusted) throw new Error("Signed update key is not trusted.");
  if (!verify(null, Buffer.from(canonicalReleasePayload(value.manifest), "utf8"), trusted.publicKeyPem, bytes)) {
    throw new Error("Signed update signature verification failed.");
  }
  return structuredClone(value.manifest);
}

export function readSignedUpdate(path, trustStore) {
  return verifySignedUpdate(boundedJson(path, MAX_SIGNED_UPDATE_BYTES, "Signed update envelope"), trustStore);
}

function verifyPortablePackage(packageRoot, releaseManifest) {
  const manifestPath = join(packageRoot, RELEASE_MANIFEST_FILE);
  const portable = boundedJson(manifestPath, 16 * 1024 * 1024, "Portable release manifest");
  assertManifestShape(portable);
  if (sha256File(manifestPath) !== releaseManifest.portableManifestSha256) throw new Error("Portable release manifest digest does not match the signed update.");
  for (const field of ["version", "commit", "platform", "architecture", "releaseId"]) {
    if (portable[field] !== releaseManifest[field]) throw new Error(`Portable release ${field} does not match the signed update.`);
  }
  const actual = listPackageFiles(packageRoot, new Set([RELEASE_MANIFEST_FILE]));
  if (JSON.stringify(actual) !== JSON.stringify(portable.files)) throw new Error("Portable release inventory verification failed.");
  return portable;
}

export function verifyReleaseBundle({ packageRoot, signedUpdatePath, trustStorePath }) {
  const trustStore = readReleaseTrustStore(trustStorePath);
  const release = readSignedUpdate(signedUpdatePath, trustStore);
  const portable = verifyPortablePackage(resolve(packageRoot), release);
  return { release, portable, trustStore };
}

function assertManagedRoot(path, label) {
  if (typeof path !== "string" || !isAbsolute(path)) throw new Error(`${label} must be an explicit absolute path.`);
  const value = resolve(path);
  if (value === parse(value).root || value === dirname(value) || value === resolve(homedir())) {
    throw new Error(`${label} cannot be a filesystem root or home directory.`);
  }
  return value;
}

function atomicWrite(path, content, mode = 0o600) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const temporary = join(dirname(path), `.${basename(path)}.${process.pid}.${Date.now()}.tmp`);
  try {
    writeFileSync(temporary, content, { encoding: "utf8", mode, flag: "wx" });
    chmodSync(temporary, mode);
    renameSync(temporary, path);
  } finally {
    if (existsSync(temporary)) rmSync(temporary, { force: true });
  }
}

function copyCompleteTree(source, destination) {
  const state = lstatSync(source);
  if (state.isSymbolicLink()) throw new Error("Release packages must not contain symlinks.");
  if (state.isFile()) {
    mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
    copyFileSync(source, destination);
    chmodSync(destination, (state.mode & 0o111) !== 0 ? 0o755 : 0o644);
    return;
  }
  if (!state.isDirectory()) throw new Error("Release packages must contain only files and directories.");
  mkdirSync(destination, { recursive: true, mode: 0o700 });
  for (const entry of readdirSync(source, { withFileTypes: true }).sort((a, b) => lexicalCompare(a.name, b.name))) {
    copyCompleteTree(join(source, entry.name), join(destination, entry.name));
  }
}

function marker(purpose) {
  return { schemaVersion: INSTALL_STATE_SCHEMA, product: "Email Shield", managedDirectory: true, purpose };
}

function assertMarker(path, purpose) {
  const value = boundedJson(path, 4_096, "Email Shield install marker");
  exactFields(value, ["schemaVersion", "product", "managedDirectory", "purpose"], "Email Shield install marker");
  if (value.schemaVersion !== INSTALL_STATE_SCHEMA || value.product !== "Email Shield" || value.managedDirectory !== true || value.purpose !== purpose) {
    throw new Error("Email Shield install marker is invalid.");
  }
}

function assertState(value) {
  exactFields(value, ["schemaVersion", "product", "activeReleaseId", "previousReleaseId", "activeVersion"], "Install state");
  if (value.schemaVersion !== INSTALL_STATE_SCHEMA || value.product !== "Email Shield" || !RELEASE_ID_PATTERN.test(value.activeReleaseId)) {
    throw new Error("Install state identity is invalid.");
  }
  if (value.previousReleaseId !== null && !RELEASE_ID_PATTERN.test(value.previousReleaseId)) throw new Error("Install rollback identity is invalid.");
  if (!VERSION_PATTERN.test(value.activeVersion)) throw new Error("Install state version is invalid.");
}

export function readInstallState(installRoot) {
  const root = assertManagedRoot(installRoot, "Install root");
  assertMarker(join(root, INSTALL_MARKER_FILE), "install");
  const state = boundedJson(join(root, INSTALL_STATE_FILE), 16_384, "Install state");
  assertState(state);
  const active = readFileSync(join(root, ACTIVE_RELEASE_FILE), "utf8").trim();
  if (active !== state.activeReleaseId) throw new Error("Install activation pointer and state do not match.");
  return state;
}

function versionParts(value) {
  const [core, prerelease = ""] = value.split("-", 2);
  return { numbers: core.split(".").map(Number), prerelease };
}

export function compareReleaseVersions(left, right) {
  if (!VERSION_PATTERN.test(left) || !VERSION_PATTERN.test(right)) throw new Error("Cannot compare an invalid release version.");
  const a = versionParts(left);
  const b = versionParts(right);
  for (let index = 0; index < 3; index++) {
    if (a.numbers[index] !== b.numbers[index]) return a.numbers[index] < b.numbers[index] ? -1 : 1;
  }
  if (a.prerelease === b.prerelease) return 0;
  if (!a.prerelease) return 1;
  if (!b.prerelease) return -1;
  return lexicalCompare(a.prerelease, b.prerelease);
}

function rootLauncher(platform) {
  if (platform === "win32") {
    return "@echo off\r\nsetlocal\r\nset \"EMAIL_SHIELD_INSTALL_ROOT=%~dp0\"\r\nset /p EMAIL_SHIELD_ACTIVE_RELEASE=<\"%EMAIL_SHIELD_INSTALL_ROOT%active-release\"\r\n\"%EMAIL_SHIELD_INSTALL_ROOT%versions\\%EMAIL_SHIELD_ACTIVE_RELEASE%\\runtime\\node.exe\" \"%EMAIL_SHIELD_INSTALL_ROOT%versions\\%EMAIL_SHIELD_ACTIVE_RELEASE%\\app\\server\\dist\\index.js\"\r\n";
  }
  return "#!/bin/sh\nset -eu\nEMAIL_SHIELD_INSTALL_ROOT=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\nEMAIL_SHIELD_ACTIVE_RELEASE=$(tr -d '\\r\\n' < \"$EMAIL_SHIELD_INSTALL_ROOT/active-release\")\ncase \"$EMAIL_SHIELD_ACTIVE_RELEASE\" in *[!0-9a-f]*|'') exit 1;; esac\nexec \"$EMAIL_SHIELD_INSTALL_ROOT/versions/$EMAIL_SHIELD_ACTIVE_RELEASE/runtime/node\" \"$EMAIL_SHIELD_INSTALL_ROOT/versions/$EMAIL_SHIELD_ACTIVE_RELEASE/app/server/dist/index.js\"\n";
}

function activate(root, release, previousReleaseId) {
  const state = {
    schemaVersion: INSTALL_STATE_SCHEMA,
    product: "Email Shield",
    activeReleaseId: release.releaseId,
    previousReleaseId,
    activeVersion: release.version,
  };
  atomicWrite(join(root, INSTALL_STATE_FILE), `${JSON.stringify(state, null, 2)}\n`);
  atomicWrite(join(root, ACTIVE_RELEASE_FILE), `${release.releaseId}\n`);
  return state;
}

function stageVerifiedRelease(root, packageRoot, signedUpdatePath, trustStore, release) {
  const versions = join(root, "versions");
  const metadata = join(root, "metadata");
  mkdirSync(versions, { recursive: true, mode: 0o700 });
  mkdirSync(metadata, { recursive: true, mode: 0o700 });
  const destination = join(versions, release.releaseId);
  if (!existsSync(destination)) {
    const staging = join(root, `.staging-${release.releaseId}`);
    if (existsSync(staging)) rmSync(staging, { recursive: true, force: true });
    try {
      copyCompleteTree(resolve(packageRoot), staging);
      verifyPortablePackage(staging, release);
      renameSync(staging, destination);
    } catch (error) {
      if (existsSync(staging)) rmSync(staging, { recursive: true, force: true });
      throw error;
    }
  } else {
    verifyPortablePackage(destination, release);
  }
  const envelope = boundedJson(signedUpdatePath, MAX_SIGNED_UPDATE_BYTES, "Signed update envelope");
  verifySignedUpdate(envelope, trustStore);
  atomicWrite(join(metadata, `${release.releaseId}.signed-update.json`), `${JSON.stringify(envelope, null, 2)}\n`);
  return destination;
}

export function installRelease({ packageRoot, signedUpdatePath, trustStorePath, installRoot }) {
  const root = assertManagedRoot(installRoot, "Install root");
  if (existsSync(root) && readdirSync(root).length !== 0) throw new Error("Fresh install root must not already contain files.");
  const { release, trustStore } = verifyReleaseBundle({ packageRoot, signedUpdatePath, trustStorePath });
  mkdirSync(root, { recursive: true, mode: 0o700 });
  try {
    atomicWrite(join(root, INSTALL_MARKER_FILE), `${JSON.stringify(marker("install"), null, 2)}\n`);
    atomicWrite(join(root, RELEASE_TRUST_FILE), `${JSON.stringify(trustStore, null, 2)}\n`);
    stageVerifiedRelease(root, packageRoot, signedUpdatePath, trustStore, release);
    atomicWrite(join(root, release.platform === "win32" ? "EmailShield.cmd" : "email-shield"), rootLauncher(release.platform), 0o755);
    return activate(root, release, null);
  } catch (error) {
    if (existsSync(root)) rmSync(root, { recursive: true, force: true });
    throw error;
  }
}

export function updateRelease({ packageRoot, signedUpdatePath, installRoot }) {
  const root = assertManagedRoot(installRoot, "Install root");
  const current = readInstallState(root);
  const trustStore = readReleaseTrustStore(join(root, RELEASE_TRUST_FILE));
  const release = readSignedUpdate(signedUpdatePath, trustStore);
  verifyPortablePackage(resolve(packageRoot), release);
  const activeRelease = readSignedUpdate(join(root, "metadata", `${current.activeReleaseId}.signed-update.json`), trustStore);
  if (release.platform !== activeRelease.platform || release.architecture !== activeRelease.architecture) {
    throw new Error("Update target must match the installed platform and architecture.");
  }
  if (compareReleaseVersions(release.version, current.activeVersion) <= 0) {
    throw new Error("Update version must be newer than the active release; use verified rollback for downgrade.");
  }
  stageVerifiedRelease(root, packageRoot, signedUpdatePath, trustStore, release);
  return activate(root, release, current.activeReleaseId);
}

export function rollbackRelease({ installRoot }) {
  const root = assertManagedRoot(installRoot, "Install root");
  const current = readInstallState(root);
  if (!current.previousReleaseId) throw new Error("No verified previous release is available for rollback.");
  const trustStore = readReleaseTrustStore(join(root, RELEASE_TRUST_FILE));
  const signedPath = join(root, "metadata", `${current.previousReleaseId}.signed-update.json`);
  const release = readSignedUpdate(signedPath, trustStore);
  if (release.releaseId !== current.previousReleaseId) throw new Error("Rollback metadata identity is invalid.");
  verifyPortablePackage(join(root, "versions", release.releaseId), release);
  return activate(root, release, current.activeReleaseId);
}

export function repairReleaseActivation({ installRoot }) {
  const root = assertManagedRoot(installRoot, "Install root");
  assertMarker(join(root, INSTALL_MARKER_FILE), "install");
  const state = boundedJson(join(root, INSTALL_STATE_FILE), 16_384, "Install state");
  assertState(state);
  const trustStore = readReleaseTrustStore(join(root, RELEASE_TRUST_FILE));
  const release = readSignedUpdate(join(root, "metadata", `${state.activeReleaseId}.signed-update.json`), trustStore);
  verifyPortablePackage(join(root, "versions", state.activeReleaseId), release);
  atomicWrite(join(root, ACTIVE_RELEASE_FILE), `${state.activeReleaseId}\n`);
  return state;
}

export function uninstallRelease({ installRoot, dataRoot = null, purgeData = false }) {
  const root = assertManagedRoot(installRoot, "Install root");
  readInstallState(root);
  if (purgeData) {
    const data = assertManagedRoot(dataRoot, "Data root");
    assertMarker(join(data, DATA_MARKER_FILE), "data");
    if (data === root || data.startsWith(`${root}${sep}`) || root.startsWith(`${data}${sep}`)) {
      throw new Error("Install and data roots must be independent managed directories.");
    }
    const knownDataName = /^(?:\.email-shield-data\.json|personal-(?:policies\.enc\.json|policy\.key)|scan-state(?:\.enc\.json|\.key)|relationship-history(?:\.enc\.json|\.key)|background-protection(?:\.enc\.json|\.key)|community-[a-z0-9.-]+|local-state-recovery-[0-9TZ.-]+-[a-f0-9]{8})$/;
    const unknown = readdirSync(data).filter((name) => !knownDataName.test(name));
    if (unknown.length) throw new Error("Data root contains files not owned by Email Shield; refusing recursive purge.");
    rmSync(data, { recursive: true, force: true });
  }
  rmSync(root, { recursive: true, force: true });
  return { programRemoved: true, dataPurged: purgeData };
}
