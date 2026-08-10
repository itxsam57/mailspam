import {
  lstatSync,
  readFileSync,
  mkdtempSync,
  mkdirSync,
  rmSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  encryptedJsonEnvelopeByteCeiling,
  readBoundedRegularFile,
  readBoundedUtf8File,
} from "../../server/src/util/localFileIntegrity.js";
import { EncryptedFilePolicyRepository } from "../../server/src/api/policyPersistence.js";
import { EncryptedFileScanStateRepository } from "../../server/src/api/scanStatePersistence.js";
import { EncryptedFileRelationshipHistoryRepository } from "../../server/src/api/relationshipHistoryPersistence.js";
import { EncryptedCommunityOutbox } from "../../server/src/community/outbox.js";
import { CommunityReporterIdentity } from "../../server/src/community/reporterIdentity.js";

const directories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-local-file-integrity-"));
  directories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of directories.splice(0).reverse()) rmSync(directory, { recursive: true, force: true });
});

describe("shared local regular-file read integrity", () => {
  it("reads only the exact validated regular-file length", () => {
    const directory = temporaryDirectory();
    const path = join(directory, "bounded.bin");
    writeFileSync(path, Buffer.from("bounded-content", "utf8"));

    const content = readBoundedRegularFile(path, { description: "Bounded test file", maxBytes: 64 });
    expect(content.toString("utf8")).toBe("bounded-content");
    content.fill(0);
    expect(readBoundedUtf8File(path, { description: "Bounded test file", maxBytes: 64 })).toBe("bounded-content");
  });

  it("rejects a sparse oversized file before allocating its content", () => {
    const directory = temporaryDirectory();
    const path = join(directory, "oversized.bin");
    writeFileSync(path, "");
    truncateSync(path, 32 * 1024 * 1024);

    expect(() => readBoundedRegularFile(path, { description: "Oversized test file", maxBytes: 1024 }))
      .toThrow("local size contract");
  });

  it("enforces exact-size key contracts", () => {
    const directory = temporaryDirectory();
    const path = join(directory, "key.bin");
    writeFileSync(path, Buffer.alloc(33, 7));

    expect(() => readBoundedRegularFile(path, {
      description: "Exact test key",
      maxBytes: 32,
      exactBytes: 32,
    })).toThrow("invalid size");
  });

  it.runIf(process.platform !== "win32")("refuses a POSIX symlink instead of following it", () => {
    const directory = temporaryDirectory();
    const target = join(directory, "target.bin");
    const link = join(directory, "link.bin");
    writeFileSync(target, "secret");
    symlinkSync(target, link);
    expect(lstatSync(link).isSymbolicLink()).toBe(true);

    expect(() => readBoundedRegularFile(link, { description: "Symlink test file", maxBytes: 64 }))
      .toThrow("could not be opened safely");
  });


  it("never deletes the last good destination when a temporary-file replacement fails", () => {
    const helperSource = readFileSync(join(process.cwd(), "src/util/localFileIntegrity.ts"), "utf8");
    expect(helperSource).toContain("renameSync(temporaryPath, destinationPath)");
    expect(helperSource).toContain("rmSync(temporaryPath, { force: true })");
    expect(helperSource).not.toContain("rmSync(destinationPath");

    for (const path of [
      "src/api/policyPersistence.ts",
      "src/api/scanStatePersistence.ts",
      "src/api/relationshipHistoryPersistence.ts",
      "src/community/outbox.ts",
      "src/community/aggregateStore.ts",
    ]) {
      const source = readFileSync(join(process.cwd(), path), "utf8");
      expect(source).toContain("replaceFileFromTemporaryPath(temporaryPath");
      expect(source).not.toMatch(/rmSync\(this\.(?:databasePath|outboxPath), \{ force: true \}\)/);
    }
  });
  it("keeps encrypted JSON file ceilings above their plaintext ceilings", () => {
    for (const plaintextBytes of [1, 1024, 8 * 1024 * 1024, 32 * 1024 * 1024]) {
      const ceiling = encryptedJsonEnvelopeByteCeiling(plaintextBytes);
      expect(ceiling).toBeGreaterThan(plaintextBytes);
      expect(ceiling).toBeGreaterThanOrEqual(512 + (4 * Math.ceil(plaintextBytes / 3)));
    }
  });
});

describe("local encrypted-store pre-allocation boundaries", () => {
  it("rejects an oversized personal-policy file before JSON/decryption work", () => {
    const directory = temporaryDirectory();
    const path = join(directory, "personal-policies.enc.json");
    writeFileSync(path, "");
    truncateSync(path, 96 * 1024 * 1024);
    const repository = new EncryptedFilePolicyRepository(directory, Buffer.alloc(32, 1));
    expect(() => repository.load("a".repeat(64))).toThrow(/local size contract/i);
  });

  it("uses a separate encrypted-envelope ceiling for scan state instead of the plaintext ceiling", () => {
    const directory = temporaryDirectory();
    const path = join(directory, "scan-state.enc.json");
    writeFileSync(path, "");
    truncateSync(path, 12 * 1024 * 1024);
    const repository = new EncryptedFileScanStateRepository(directory, Buffer.alloc(32, 2));
    expect(() => repository.list("b".repeat(64))).toThrow(/local size contract/i);
  });

  it("uses a separate encrypted-envelope ceiling for relationship history", () => {
    const directory = temporaryDirectory();
    const path = join(directory, "relationship-history.enc.json");
    writeFileSync(path, "");
    truncateSync(path, 48 * 1024 * 1024);
    const repository = new EncryptedFileRelationshipHistoryRepository(directory, Buffer.alloc(32, 3));
    expect(() => repository.workerSnapshot("c".repeat(64))).toThrow(/local size contract/i);
  });

  it("rejects an oversized community outbox before creating or reading its key", () => {
    const directory = temporaryDirectory();
    const path = join(directory, "community-outbox.enc.json");
    writeFileSync(path, "");
    truncateSync(path, 180 * 1024 * 1024);
    const outbox = new EncryptedCommunityOutbox(directory);
    expect(() => outbox.count()).toThrow(/local size contract/i);
  });

  it("rejects oversized reporter identity keys through the exact-size contract", () => {
    const directory = temporaryDirectory();
    mkdirSync(directory, { recursive: true });
    writeFileSync(join(directory, "community-reporter.key"), Buffer.alloc(33, 4));
    const identity = new CommunityReporterIdentity(directory);
    expect(() => identity.proofForAccount("d".repeat(64))).toThrow("Community reporter identity key is invalid");
  });
});
