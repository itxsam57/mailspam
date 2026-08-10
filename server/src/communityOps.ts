import { resolve } from "node:path";
import {
  createEncryptedCommunityBackup,
  prepareCommunitySigningRotation,
  readCommunityBackupPassphraseFile,
  restoreEncryptedCommunityBackup,
  type CommunitySigningKeys,
} from "./community/operations.js";

function signingKeysFromEnvironment(): CommunitySigningKeys | undefined {
  const privatePem = process.env.EMAIL_SHIELD_COMMUNITY_PRIVATE_KEY?.replace(/\\n/g, "\n");
  const publicPem = process.env.EMAIL_SHIELD_COMMUNITY_PUBLIC_KEY?.replace(/\\n/g, "\n");
  if (Boolean(privatePem) !== Boolean(publicPem)) {
    throw new Error("Configured community signing requires both EMAIL_SHIELD_COMMUNITY_PRIVATE_KEY and EMAIL_SHIELD_COMMUNITY_PUBLIC_KEY.");
  }
  return privatePem && publicPem ? { privatePem, publicPem } : undefined;
}

function requirePassphrase(): Buffer {
  const path = process.env.EMAIL_SHIELD_COMMUNITY_BACKUP_PASSPHRASE_FILE?.trim();
  if (!path) {
    throw new Error("Set EMAIL_SHIELD_COMMUNITY_BACKUP_PASSPHRASE_FILE to a protected passphrase file. The passphrase is never accepted in argv.");
  }
  return readCommunityBackupPassphraseFile(resolve(path));
}

function usage(): never {
  throw new Error(
    "Usage: communityOps backup <data-dir> <backup-file> | restore <backup-file> <new-data-dir> | prepare-rotation <data-dir> <new-package-dir>",
  );
}

async function main(): Promise<void> {
  const [command, first, second, ...rest] = process.argv.slice(2);
  if (!command || !first || !second || rest.length > 0) usage();

  if (command === "backup") {
    const passphrase = requirePassphrase();
    try {
      const result = createEncryptedCommunityBackup({
        dataDirectory: resolve(first),
        backupPath: resolve(second),
        passphrase,
        configuredSigningKeys: signingKeysFromEnvironment(),
      });
      process.stdout.write(`${JSON.stringify(result)}\n`);
    } finally {
      passphrase.fill(0);
    }
    return;
  }

  if (command === "restore") {
    const passphrase = requirePassphrase();
    try {
      const result = restoreEncryptedCommunityBackup({
        backupPath: resolve(first),
        targetDataDirectory: resolve(second),
        passphrase,
      });
      process.stdout.write(`${JSON.stringify(result)}\n`);
    } finally {
      passphrase.fill(0);
    }
    return;
  }

  if (command === "prepare-rotation") {
    const result = prepareCommunitySigningRotation({
      dataDirectory: resolve(first),
      outputDirectory: resolve(second),
      configuredCurrentSigningKeys: signingKeysFromEnvironment(),
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }

  usage();
}

main().catch((error) => {
  process.stderr.write(`Community operations failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
