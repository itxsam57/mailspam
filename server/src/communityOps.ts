import { resolve } from "node:path";
import { EncryptedCommunityAggregateStore } from "./community/aggregateStore.js";
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

function requireReviewReason(): string {
  const reason = process.env.EMAIL_SHIELD_COMMUNITY_REVIEW_REASON?.trim();
  if (!reason) {
    throw new Error("Set EMAIL_SHIELD_COMMUNITY_REVIEW_REASON for review-resolve. Review reasons are not accepted in argv.");
  }
  return reason;
}

function usage(): never {
  throw new Error(
    "Usage: communityOps backup <data-dir> <backup-file> | restore <backup-file> <new-data-dir> | prepare-rotation <data-dir> <new-package-dir> | review-list <data-dir> | review-resolve <data-dir> <campaign-fingerprint> <approve|reject> <reviewer-id>",
  );
}

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  if (!command) usage();

  if (command === "backup") {
    if (args.length !== 2) usage();
    const [dataDir, backupFile] = args as [string, string];
    const passphrase = requirePassphrase();
    try {
      const result = createEncryptedCommunityBackup({
        dataDirectory: resolve(dataDir),
        backupPath: resolve(backupFile),
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
    if (args.length !== 2) usage();
    const [backupFile, targetDir] = args as [string, string];
    const passphrase = requirePassphrase();
    try {
      const result = restoreEncryptedCommunityBackup({
        backupPath: resolve(backupFile),
        targetDataDirectory: resolve(targetDir),
        passphrase,
      });
      process.stdout.write(`${JSON.stringify(result)}\n`);
    } finally {
      passphrase.fill(0);
    }
    return;
  }

  if (command === "prepare-rotation") {
    if (args.length !== 2) usage();
    const [dataDir, outputDir] = args as [string, string];
    const result = prepareCommunitySigningRotation({
      dataDirectory: resolve(dataDir),
      outputDirectory: resolve(outputDir),
      configuredCurrentSigningKeys: signingKeysFromEnvironment(),
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return;
  }

  if (command === "review-list") {
    if (args.length !== 1) usage();
    const store = new EncryptedCommunityAggregateStore(resolve(args[0]!));
    try {
      process.stdout.write(`${JSON.stringify(store.listReviewCandidates())}\n`);
    } finally {
      store.close();
    }
    return;
  }

  if (command === "review-resolve") {
    if (args.length !== 4) usage();
    const [dataDir, campaignFingerprint, decisionArg, reviewerId] = args as [string, string, string, string];
    const decision = decisionArg === "approve" ? "approved" : decisionArg === "reject" ? "rejected" : null;
    if (!decision) usage();
    const store = new EncryptedCommunityAggregateStore(resolve(dataDir));
    try {
      const result = store.resolveReviewCandidate({
        campaignFingerprint,
        decision,
        reviewerId,
        reason: requireReviewReason(),
      });
      process.stdout.write(`${JSON.stringify(result)}\n`);
    } finally {
      store.close();
    }
    return;
  }

  usage();
}

main().catch((error) => {
  process.stderr.write(`Community operations failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
