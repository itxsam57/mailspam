import { generateKeyPairSync } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
// @ts-expect-error Release automation is deliberately executable JavaScript shared with packaged tools.
import * as releaseLifecycle from "../../scripts/release/release-lifecycle-lib.mjs";
// @ts-expect-error Release automation is deliberately executable JavaScript shared with packaged tools.
import * as portablePackage from "../../scripts/release/portable-package-lib.mjs";

const {
  ACTIVE_RELEASE_FILE,
  createSignedUpdate,
  DATA_MARKER_FILE,
  installRelease,
  readInstallState,
  releaseKeyId,
  repairReleaseActivation,
  rollbackRelease,
  uninstallRelease,
  updateRelease,
  verifyReleaseBundle,
} = releaseLifecycle;
const {
  listPackageFiles,
  releaseId,
  RELEASE_MANIFEST_FILE,
} = portablePackage;

const temporaryRoots: string[] = [];

function temporaryRoot(): string {
  const value = mkdtempSync(join(tmpdir(), "email-shield-release-test-"));
  temporaryRoots.push(value);
  return value;
}

afterEach(() => {
  while (temporaryRoots.length) rmSync(temporaryRoots.pop()!, { recursive: true, force: true });
});

function signingMaterial() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const trustStore = {
    schemaVersion: 1,
    product: "Email Shield",
    keys: [{ keyId: releaseKeyId(publicKey), publicKeyPem }],
  };
  return { privateKeyPem, trustStore };
}

function buildFixture(root: string, version: string, marker: string, privateKeyPem: string) {
  const packageRoot = join(root, `package-${version}`);
  mkdirSync(join(packageRoot, "app/server/dist"), { recursive: true });
  mkdirSync(join(packageRoot, "runtime"), { recursive: true });
  writeFileSync(join(packageRoot, "app/server/dist/index.js"), `export const marker = ${JSON.stringify(marker)};\n`);
  writeFileSync(join(packageRoot, "runtime", process.platform === "win32" ? "node.exe" : "node"), "fixture-runtime\n");
  const manifest = {
    schemaVersion: 1,
    product: "Email Shield",
    version,
    commit: marker.repeat(40).slice(0, 40).replace(/[^a-f0-9]/g, "a"),
    platform: process.platform,
    architecture: process.arch,
    nodeVersion: process.versions.node,
    entrypoint: "app/server/dist/index.js",
    launcher: process.platform === "win32" ? "EmailShield.cmd" : "email-shield",
    productionPackages: [],
    files: listPackageFiles(packageRoot, new Set([RELEASE_MANIFEST_FILE])),
    artifactBytes: 0,
    releaseId: "",
  };
  manifest.artifactBytes = manifest.files.reduce((total: number, file: { bytes: number }) => total + file.bytes, 0);
  manifest.releaseId = releaseId(manifest);
  const manifestPath = join(packageRoot, RELEASE_MANIFEST_FILE);
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  const signedUpdatePath = join(root, `${version}.signed-update.json`);
  writeFileSync(signedUpdatePath, `${JSON.stringify(createSignedUpdate(manifest, privateKeyPem), null, 2)}\n`);
  return { packageRoot, manifest, manifestPath, signedUpdatePath };
}

function writeTrustStore(root: string, trustStore: unknown): string {
  const path = join(root, "release-trust.json");
  writeFileSync(path, `${JSON.stringify(trustStore, null, 2)}\n`);
  return path;
}

function dataMarker(): string {
  return `${JSON.stringify({ schemaVersion: 1, product: "Email Shield", managedDirectory: true, purpose: "data" }, null, 2)}\n`;
}

describe("signed release installation, update and rollback lifecycle", () => {
  it("verifies every package byte, stages a newer release, and performs only a verified one-step rollback", () => {
    const root = temporaryRoot();
    const { privateKeyPem, trustStore } = signingMaterial();
    const trustStorePath = writeTrustStore(root, trustStore);
    const first = buildFixture(root, "1.0.0", "a", privateKeyPem);
    const second = buildFixture(root, "1.1.0", "b", privateKeyPem);
    const installRoot = join(root, "installed", "email-shield");

    expect(verifyReleaseBundle({ packageRoot: first.packageRoot, signedUpdatePath: first.signedUpdatePath, trustStorePath }).release.releaseId)
      .toBe(first.manifest.releaseId);
    expect(installRelease({ ...first, trustStorePath, installRoot }).activeVersion).toBe("1.0.0");
    expect(readInstallState(installRoot).activeReleaseId).toBe(first.manifest.releaseId);

    const updated = updateRelease({ ...second, installRoot });
    expect(updated.activeReleaseId).toBe(second.manifest.releaseId);
    expect(updated.previousReleaseId).toBe(first.manifest.releaseId);
    expect(readFileSync(join(installRoot, ACTIVE_RELEASE_FILE), "utf8").trim()).toBe(second.manifest.releaseId);

    const rolledBack = rollbackRelease({ installRoot });
    expect(rolledBack.activeReleaseId).toBe(first.manifest.releaseId);
    expect(rolledBack.previousReleaseId).toBe(second.manifest.releaseId);
    expect(readInstallState(installRoot).activeVersion).toBe("1.0.0");
  });

  it("rejects tampering, untrusted signatures, schema drift and non-newer update installation", () => {
    const root = temporaryRoot();
    const signing = signingMaterial();
    const other = signingMaterial();
    const trustStorePath = writeTrustStore(root, signing.trustStore);
    const first = buildFixture(root, "2.0.0", "c", signing.privateKeyPem);
    const same = buildFixture(root, "2.0.0", "d", signing.privateKeyPem);
    const untrusted = buildFixture(root, "2.1.0", "e", other.privateKeyPem);
    const installRoot = join(root, "installed", "email-shield");
    installRelease({ ...first, trustStorePath, installRoot });

    expect(() => updateRelease({ ...same, installRoot })).toThrow(/newer/);
    expect(() => updateRelease({ ...untrusted, installRoot })).toThrow(/not trusted/);

    writeFileSync(join(first.packageRoot, "app/server/dist/index.js"), "tampered\n");
    expect(() => verifyReleaseBundle({ packageRoot: first.packageRoot, signedUpdatePath: first.signedUpdatePath, trustStorePath }))
      .toThrow(/inventory/);

    const envelope = JSON.parse(readFileSync(same.signedUpdatePath, "utf8"));
    envelope.extra = true;
    writeFileSync(same.signedUpdatePath, JSON.stringify(envelope));
    expect(() => updateRelease({ ...same, installRoot })).toThrow(/fields/);
  });

  it("fails closed on activation mismatch and repairs only after re-verifying the signed installed package", () => {
    const root = temporaryRoot();
    const { privateKeyPem, trustStore } = signingMaterial();
    const trustStorePath = writeTrustStore(root, trustStore);
    const release = buildFixture(root, "3.0.0", "f", privateKeyPem);
    const installRoot = join(root, "installed", "email-shield");
    installRelease({ ...release, trustStorePath, installRoot });
    writeFileSync(join(installRoot, ACTIVE_RELEASE_FILE), `${"0".repeat(64)}\n`);
    expect(() => readInstallState(installRoot)).toThrow(/do not match/);
    expect(repairReleaseActivation({ installRoot }).activeReleaseId).toBe(release.manifest.releaseId);
    expect(readInstallState(installRoot).activeReleaseId).toBe(release.manifest.releaseId);
  });

  it("preserves user data by default and purges only an independently marked, known-content data root", () => {
    const root = temporaryRoot();
    const { privateKeyPem, trustStore } = signingMaterial();
    const trustStorePath = writeTrustStore(root, trustStore);
    const release = buildFixture(root, "4.0.0", "a", privateKeyPem);
    const installRoot = join(root, "installed", "email-shield");
    const dataRoot = join(root, "data", "email-shield");
    mkdirSync(dataRoot, { recursive: true });
    writeFileSync(join(dataRoot, DATA_MARKER_FILE), dataMarker());
    writeFileSync(join(dataRoot, "personal-policies.enc.json"), "protected-state");

    installRelease({ ...release, trustStorePath, installRoot });
    expect(uninstallRelease({ installRoot }).dataPurged).toBe(false);
    expect(existsSync(dataRoot)).toBe(true);

    installRelease({ ...release, trustStorePath, installRoot });
    expect(uninstallRelease({ installRoot, dataRoot, purgeData: true }).dataPurged).toBe(true);
    expect(existsSync(dataRoot)).toBe(false);
  });

  it("refuses broad purge targets, foreign data and symlinked package content", () => {
    const root = temporaryRoot();
    const { privateKeyPem, trustStore } = signingMaterial();
    const trustStorePath = writeTrustStore(root, trustStore);
    const release = buildFixture(root, "5.0.0", "b", privateKeyPem);
    const installRoot = join(root, "installed", "email-shield");
    const dataRoot = join(root, "data", "email-shield");
    mkdirSync(dataRoot, { recursive: true });
    writeFileSync(join(dataRoot, DATA_MARKER_FILE), dataMarker());
    writeFileSync(join(dataRoot, "not-owned.txt"), "do not remove");
    installRelease({ ...release, trustStorePath, installRoot });
    expect(() => uninstallRelease({ installRoot, dataRoot, purgeData: true })).toThrow(/not owned/);
    expect(existsSync(installRoot)).toBe(true);

    const symlinked = buildFixture(root, "5.1.0", "c", privateKeyPem);
    const linkTarget = process.platform === "win32"
      ? join(symlinked.packageRoot, "app/server/dist")
      : join(symlinked.packageRoot, "app/server/dist/index.js");
    symlinkSync(linkTarget, join(symlinked.packageRoot, "unexpected-link"), process.platform === "win32" ? "junction" : "file");
    expect(() => verifyReleaseBundle({ packageRoot: symlinked.packageRoot, signedUpdatePath: symlinked.signedUpdatePath, trustStorePath }))
      .toThrow(/symlink/);
  });
});
