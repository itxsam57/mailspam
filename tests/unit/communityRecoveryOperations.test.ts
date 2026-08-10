import { generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CommunityNetwork } from "../../server/src/community/network.js";
import {
  createEncryptedCommunityBackup,
  prepareCommunitySigningRotation,
  readCommunityBackupPassphraseFile,
  restoreEncryptedCommunityBackup,
  verifyCommunitySigningRotationPackage,
  type CommunitySigningKeys,
} from "../../server/src/community/operations.js";
import { CommunityFeedSigner } from "../../server/src/community/signing.js";
import {
  COMMUNITY_REPORT_KEY_FILE,
  COMMUNITY_SIGNING_PRIVATE_FILE,
  COMMUNITY_SIGNING_PUBLIC_FILE,
} from "../../server/src/community/storageFiles.js";
import type { CommunityReportSubmission } from "../../server/src/community/types.js";

const paths: string[] = [];
const PASSPHRASE = "correct horse battery staple for email shield";

function tempPath(label: string): string {
  const value = mkdtempSync(join(tmpdir(), `email-shield-${label}-`));
  paths.push(value);
  return value;
}

function absentChild(parent: string, name: string): string {
  const value = join(parent, name);
  paths.push(value);
  return value;
}

function report(seed: string): CommunityReportSubmission {
  const campaign = seed.repeat(64).slice(0, 64).replace(/[^a-f0-9]/g, "a");
  return {
    schemaVersion: 1,
    reporterProof: "b".repeat(64),
    campaignFingerprint: campaign,
    reportedAt: new Date().toISOString(),
    indicators: [
      { type: "campaign", value: campaign },
      { type: "url_domain", value: `${seed}.example.test` },
    ],
    evidenceCodes: ["RECOVERY_TEST"],
    evidenceScore: 9,
    verdict: "high_risk",
  };
}

function generateSigningKeys(): CommunitySigningKeys {
  const pair = generateKeyPairSync("ed25519");
  return {
    privatePem: pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

afterEach(() => {
  for (const path of paths.splice(0).reverse()) rmSync(path, { recursive: true, force: true });
});

describe("encrypted community disaster recovery", () => {
  it("backs up and atomically restores real aggregate data and signing identity without plaintext leakage", () => {
    const source = tempPath("community-recovery-source");
    const network = new CommunityNetwork({ dataDirectory: source, serverEnabled: true });
    network.acceptExternalReport(report("c"));
    const originalInfo = network.publicInfo();
    const originalStats = originalInfo.stats;
    const backup = absentChild(tempPath("community-recovery-backup-parent"), "community-backup.eshield");

    const created = createEncryptedCommunityBackup({
      dataDirectory: source,
      backupPath: backup,
      passphrase: PASSPHRASE,
    });
    expect(created).toMatchObject({
      signingKeyId: originalInfo.keyId,
      aggregateStoragePresent: true,
    });
    const rawBackup = readFileSync(backup, "utf8");
    expect(rawBackup).not.toContain("BEGIN PRIVATE KEY");
    expect(rawBackup).not.toContain("example.test");
    expect(rawBackup).not.toContain("RECOVERY_TEST");

    const restoreParent = tempPath("community-recovery-target-parent");
    const target = absentChild(restoreParent, "restored-data");
    const restored = restoreEncryptedCommunityBackup({
      backupPath: backup,
      targetDataDirectory: target,
      passphrase: PASSPHRASE,
    });
    expect(restored).toMatchObject({
      signingKeyId: originalInfo.keyId,
      aggregateStoragePresent: true,
    });
    const recoveredNetwork = new CommunityNetwork({ dataDirectory: target, serverEnabled: true });
    expect(recoveredNetwork.publicInfo().keyId).toBe(originalInfo.keyId);
    expect(recoveredNetwork.publicInfo().stats).toEqual(originalStats);
  });

  it("rejects a wrong passphrase without creating the target directory", () => {
    const source = tempPath("community-wrong-pass-source");
    new CommunityNetwork({ dataDirectory: source, serverEnabled: true });
    const backup = absentChild(tempPath("community-wrong-pass-backup"), "backup.eshield");
    createEncryptedCommunityBackup({ dataDirectory: source, backupPath: backup, passphrase: PASSPHRASE });
    const target = absentChild(tempPath("community-wrong-pass-target"), "restored");

    expect(() => restoreEncryptedCommunityBackup({
      backupPath: backup,
      targetDataDirectory: target,
      passphrase: "this is definitely the wrong passphrase",
    })).toThrow("authentication failed");
    expect(existsSync(target)).toBe(false);
  });

  it("rejects a tampered authenticated backup", () => {
    const source = tempPath("community-tamper-source");
    new CommunityNetwork({ dataDirectory: source, serverEnabled: true });
    const backup = absentChild(tempPath("community-tamper-backup"), "backup.eshield");
    createEncryptedCommunityBackup({ dataDirectory: source, backupPath: backup, passphrase: PASSPHRASE });
    const document = JSON.parse(readFileSync(backup, "utf8")) as { ciphertext: string };
    const original = document.ciphertext;
    document.ciphertext = `${original.slice(0, -4)}${original.slice(-4) === "AAAA" ? "AAAB" : "AAAA"}`;
    writeFileSync(backup, JSON.stringify(document));
    const target = absentChild(tempPath("community-tamper-target"), "restored");

    expect(() => restoreEncryptedCommunityBackup({
      backupPath: backup,
      targetDataDirectory: target,
      passphrase: PASSPHRASE,
    })).toThrow();
    expect(existsSync(target)).toBe(false);
  });

  it("refuses to back up a partial aggregate storage pair", () => {
    const source = tempPath("community-partial-source");
    new CommunityNetwork({ dataDirectory: source, serverEnabled: true });
    writeFileSync(join(source, COMMUNITY_REPORT_KEY_FILE), Buffer.alloc(32, 7));
    const backup = absentChild(tempPath("community-partial-backup"), "backup.eshield");

    expect(() => createEncryptedCommunityBackup({
      dataDirectory: source,
      backupPath: backup,
      passphrase: PASSPHRASE,
    })).toThrow("aggregate storage is incomplete");
    expect(existsSync(backup)).toBe(false);
  });

  it("refuses to restore over any existing target path", () => {
    const source = tempPath("community-existing-source");
    new CommunityNetwork({ dataDirectory: source, serverEnabled: true });
    const backup = absentChild(tempPath("community-existing-backup"), "backup.eshield");
    createEncryptedCommunityBackup({ dataDirectory: source, backupPath: backup, passphrase: PASSPHRASE });
    const target = tempPath("community-existing-target");

    expect(() => restoreEncryptedCommunityBackup({
      backupPath: backup,
      targetDataDirectory: target,
      passphrase: PASSPHRASE,
    })).toThrow("target already exists");
  });

  it("can preserve externally configured signing identity inside the encrypted recovery bundle", () => {
    const source = tempPath("community-configured-signing-source");
    const configured = generateSigningKeys();
    const expectedKeyId = new CommunityFeedSigner(source, configured.privatePem, configured.publicPem).keyId;
    const backup = absentChild(tempPath("community-configured-signing-backup"), "backup.eshield");
    createEncryptedCommunityBackup({
      dataDirectory: source,
      backupPath: backup,
      passphrase: PASSPHRASE,
      configuredSigningKeys: configured,
    });
    const target = absentChild(tempPath("community-configured-signing-target"), "restored");

    const restored = restoreEncryptedCommunityBackup({
      backupPath: backup,
      targetDataDirectory: target,
      passphrase: PASSPHRASE,
    });
    expect(restored.signingKeyId).toBe(expectedKeyId);
    expect(readFileSync(join(target, COMMUNITY_SIGNING_PUBLIC_FILE), "utf8")).toBe(configured.publicPem);
    expect(readFileSync(join(target, COMMUNITY_SIGNING_PRIVATE_FILE), "utf8")).toBe(configured.privatePem);
  });

  it("reads a protected passphrase file with a full CRLF ending removed", () => {
    const directory = tempPath("community-passphrase-file");
    const file = join(directory, "passphrase.txt");
    writeFileSync(file, `${PASSPHRASE}\r\n`, { mode: 0o600 });
    const value = readCommunityBackupPassphraseFile(file);
    try {
      expect(value.toString("utf8")).toBe(PASSPHRASE);
    } finally {
      value.fill(0);
    }
  });

  it("rejects a group/world-readable passphrase file on POSIX", () => {
    if (process.platform === "win32") return;
    const directory = tempPath("community-passphrase-mode");
    const file = join(directory, "passphrase.txt");
    writeFileSync(file, PASSPHRASE, { mode: 0o600 });
    chmodSync(file, 0o644);
    expect(() => readCommunityBackupPassphraseFile(file)).toThrow("group or other users");
  });

  it("rejects a symlinked passphrase file on POSIX", () => {
    if (process.platform === "win32") return;
    const directory = tempPath("community-passphrase-symlink");
    const target = join(directory, "actual-secret.txt");
    const link = join(directory, "passphrase.txt");
    writeFileSync(target, PASSPHRASE, { mode: 0o600 });
    symlinkSync(target, link);
    expect(() => readCommunityBackupPassphraseFile(link)).toThrow("opened safely");
  });

  it("rejects short backup passphrases", () => {
    const source = tempPath("community-short-pass-source");
    new CommunityNetwork({ dataDirectory: source, serverEnabled: true });
    const backup = absentChild(tempPath("community-short-pass-backup"), "backup.eshield");
    expect(() => createEncryptedCommunityBackup({
      dataDirectory: source,
      backupPath: backup,
      passphrase: "too-short",
    })).toThrow("passphrase");
  });
});

describe("community signing rotation preparation", () => {
  it("creates a self-verifying two-key overlap package without replacing the active signer", () => {
    const source = tempPath("community-rotation-source");
    const network = new CommunityNetwork({ dataDirectory: source, serverEnabled: true });
    const activeKeyId = network.publicInfo().keyId;
    const output = absentChild(tempPath("community-rotation-output-parent"), "rotation-package");

    const prepared = prepareCommunitySigningRotation({ dataDirectory: source, outputDirectory: output });
    const manifest = verifyCommunitySigningRotationPackage(output);
    expect(prepared.currentKeyId).toBe(activeKeyId);
    expect(prepared.nextKeyId).not.toBe(activeKeyId);
    expect(manifest.currentKeyId).toBe(activeKeyId);
    expect(manifest.nextKeyId).toBe(prepared.nextKeyId);
    expect(manifest.sequence).toEqual([
      "deploy-overlap-trust",
      "verify-current-feed",
      "activate-next-signing-key",
      "verify-next-feed",
      "retire-current-trust-after-overlap",
    ]);
    expect(new CommunityNetwork({ dataDirectory: source, serverEnabled: true }).publicInfo().keyId).toBe(activeKeyId);
    expect(readFileSync(prepared.manifestPath, "utf8")).not.toContain("PRIVATE KEY");
    if (process.platform !== "win32") {
      expect(statSync(prepared.nextPrivateKeyPath).mode & 0o777).toBe(0o600);
    }
  });

  it("refuses to overwrite an existing rotation package path", () => {
    const source = tempPath("community-rotation-existing-source");
    new CommunityNetwork({ dataDirectory: source, serverEnabled: true });
    const output = tempPath("community-rotation-existing-output");
    expect(() => prepareCommunitySigningRotation({ dataDirectory: source, outputDirectory: output })).toThrow("already exists");
  });

  it("supports an externally configured current signing pair without writing it into the source directory", () => {
    const source = tempPath("community-rotation-configured-source");
    const configured = generateSigningKeys();
    const expected = new CommunityFeedSigner(source, configured.privatePem, configured.publicPem).keyId;
    const output = absentChild(tempPath("community-rotation-configured-output"), "package");

    const prepared = prepareCommunitySigningRotation({
      dataDirectory: source,
      outputDirectory: output,
      configuredCurrentSigningKeys: configured,
    });
    expect(prepared.currentKeyId).toBe(expected);
    expect(existsSync(join(source, COMMUNITY_SIGNING_PRIVATE_FILE))).toBe(false);
    expect(existsSync(join(source, COMMUNITY_SIGNING_PUBLIC_FILE))).toBe(false);
  });
});
