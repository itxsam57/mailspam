import { createHash, randomBytes } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, join } from "node:path";
import {
  BACKGROUND_PROTECTION_ENCRYPTED_DATABASE_MAX_BYTES,
  createDefaultBackgroundProtectionRepository,
} from "./backgroundProtectionPersistence.js";
import {
  createDefaultPersonalPolicyRepository,
  POLICY_ENCRYPTED_DATABASE_MAX_BYTES,
} from "./policyPersistence.js";
import {
  createDefaultRelationshipHistoryRepository,
  RELATIONSHIP_HISTORY_ENCRYPTED_DATABASE_MAX_BYTES,
} from "./relationshipHistoryPersistence.js";
import {
  createDefaultScanStateRepository,
  SCAN_STATE_ENCRYPTED_DATABASE_MAX_BYTES,
} from "./scanStatePersistence.js";
import type { CredentialVault } from "../security/credentialVault.js";
import { getRuntimeCredentialVault } from "../security/credentialVaultFactory.js";
import { defaultEmailShieldDataDirectory } from "../security/dataDirectory.js";
import { UnreadableEncryptedStateError } from "../security/dataBoundEncryptionKey.js";
import { ensureManagedDataDirectory } from "../security/managedDataDirectory.js";
import { readBoundedRegularFile } from "../util/localFileIntegrity.js";

const RECOVERY_REASON = "unreadable-encrypted-local-state";

interface RecoveryTarget {
  readonly fileName: string;
  readonly maxBytes: number;
  probe(dataDirectory: string, credentialVault: CredentialVault, platform: NodeJS.Platform): Promise<void>;
}

const RECOVERY_TARGETS: readonly RecoveryTarget[] = [
  {
    fileName: "personal-policies.enc.json",
    maxBytes: POLICY_ENCRYPTED_DATABASE_MAX_BYTES,
    probe: async (dataDirectory, credentialVault, platform) => {
      await createDefaultPersonalPolicyRepository({ dataDirectory, credentialVault, platform });
    },
  },
  {
    fileName: "scan-state.enc.json",
    maxBytes: SCAN_STATE_ENCRYPTED_DATABASE_MAX_BYTES,
    probe: async (dataDirectory, credentialVault, platform) => {
      await createDefaultScanStateRepository({ dataDirectory, credentialVault, platform });
    },
  },
  {
    fileName: "relationship-history.enc.json",
    maxBytes: RELATIONSHIP_HISTORY_ENCRYPTED_DATABASE_MAX_BYTES,
    probe: async (dataDirectory, credentialVault, platform) => {
      await createDefaultRelationshipHistoryRepository({ dataDirectory, credentialVault, platform });
    },
  },
  {
    fileName: "background-protection.enc.json",
    maxBytes: BACKGROUND_PROTECTION_ENCRYPTED_DATABASE_MAX_BYTES,
    probe: async (dataDirectory, credentialVault, platform) => {
      await createDefaultBackgroundProtectionRepository({ dataDirectory, credentialVault, platform });
    },
  },
];

export interface LocalStateRecoveryOptions {
  dataDirectory?: string;
  credentialVault?: CredentialVault;
  platform?: NodeJS.Platform;
  now?: Date;
}

export interface LocalStateRecoveryResult {
  archiveDirectory: string | null;
  archivedFiles: readonly string[];
}

interface ArchivedFileManifest {
  name: string;
  size: number;
  sha256: string;
}

function inspectRecoveryFile(path: string, maxBytes: number): ArchivedFileManifest {
  let bytes: Buffer;
  try {
    bytes = readBoundedRegularFile(path, {
      description: basename(path),
      maxBytes,
    });
  } catch {
    throw new Error(`${basename(path)} is not a bounded regular encrypted-state file; recovery stopped without moving data.`);
  }
  return {
    name: basename(path),
    size: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

function createArchiveDirectory(dataDirectory: string, now: Date): string {
  const timestamp = now.toISOString().replace(/[:.]/g, "-");
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const path = join(dataDirectory, `local-state-recovery-${timestamp}-${randomBytes(4).toString("hex")}`);
    if (existsSync(path)) continue;
    mkdirSync(path, { mode: 0o700 });
    return path;
  }
  throw new Error("A unique local-state recovery archive could not be created.");
}

/**
 * Authenticates each known encrypted store independently and archives only
 * stores whose data-bound and legacy keys both fail. Files are renamed within
 * the managed data root, never deleted or decrypted, and their digests are
 * recorded so a future key-restoration workflow can verify exact provenance.
 */
export async function archiveUnreadableLocalState(
  options: LocalStateRecoveryOptions = {},
): Promise<LocalStateRecoveryResult> {
  const dataDirectory = options.dataDirectory ?? defaultEmailShieldDataDirectory();
  const platform = options.platform ?? process.platform;
  const credentialVault = options.credentialVault ?? getRuntimeCredentialVault();

  if (!credentialVault.capabilities().available) {
    throw new Error("Local-state recovery requires the platform credential vault; no files were moved.");
  }
  ensureManagedDataDirectory(dataDirectory);

  const unreadable: Array<{ path: string; target: RecoveryTarget; manifest: ArchivedFileManifest }> = [];
  for (const target of RECOVERY_TARGETS) {
    const path = join(dataDirectory, target.fileName);
    if (!existsSync(path)) continue;
    const manifest = inspectRecoveryFile(path, target.maxBytes);
    try {
      await target.probe(dataDirectory, credentialVault, platform);
    } catch (error) {
      if (!(error instanceof UnreadableEncryptedStateError)) throw error;
      unreadable.push({ path, target, manifest });
    }
  }

  if (unreadable.length === 0) return { archiveDirectory: null, archivedFiles: [] };

  const recoveryTime = options.now ?? new Date();
  const archiveDirectory = createArchiveDirectory(dataDirectory, recoveryTime);
  const moved: Array<{ source: string; destination: string }> = [];
  try {
    for (const entry of unreadable) {
      const destination = join(archiveDirectory, entry.manifest.name);
      renameSync(entry.path, destination);
      moved.push({ source: entry.path, destination });
      const archived = inspectRecoveryFile(destination, entry.target.maxBytes);
      if (archived.size !== entry.manifest.size || archived.sha256 !== entry.manifest.sha256) {
        throw new Error(`${entry.manifest.name} changed during recovery; rollback was attempted.`);
      }
    }
    const manifest = {
      schemaVersion: 1,
      product: "Email Shield",
      createdAt: recoveryTime.toISOString(),
      reason: RECOVERY_REASON,
      files: unreadable.map((entry) => entry.manifest),
    };
    writeFileSync(join(archiveDirectory, "recovery-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, {
      encoding: "utf8",
      mode: 0o600,
      flag: "wx",
    });
  } catch (error) {
    let rollbackComplete = true;
    for (const entry of moved.reverse()) {
      if (!existsSync(entry.destination)) continue;
      if (existsSync(entry.source)) {
        rollbackComplete = false;
        continue;
      }
      try {
        renameSync(entry.destination, entry.source);
      } catch {
        rollbackComplete = false;
      }
    }
    if (rollbackComplete) {
      rmSync(archiveDirectory, { recursive: true, force: true });
      throw error;
    }
    throw new Error(`Local-state recovery could not fully roll back; preserved recovery archive at ${archiveDirectory}.`);
  }

  return {
    archiveDirectory,
    archivedFiles: unreadable.map((entry) => entry.manifest.name),
  };
}
