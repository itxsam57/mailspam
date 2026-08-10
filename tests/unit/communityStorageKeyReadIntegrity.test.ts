import { existsSync, lstatSync, mkdtempSync, readFileSync, rmSync, symlinkSync, truncateSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EncryptedCommunityAggregateStore } from "../../server/src/community/aggregateStore.js";
import { COMMUNITY_STORAGE_KEY_BYTES } from "../../server/src/community/resourceLimits.js";
import {
  COMMUNITY_REPORT_KEY_FILE,
} from "../../server/src/community/storageFiles.js";
import type { CommunityReportSubmission } from "../../server/src/community/types.js";

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories.splice(0).reverse()) rmSync(directory, { recursive: true, force: true });
});

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-community-key-read-"));
  directories.push(directory);
  return directory;
}

function report(seed = "a"): CommunityReportSubmission {
  const fingerprint = seed.repeat(64).slice(0, 64).replace(/[^a-f0-9]/g, "a");
  return {
    schemaVersion: 1,
    reporterProof: "b".repeat(64),
    campaignFingerprint: fingerprint,
    reportedAt: new Date().toISOString(),
    verdict: "high_risk",
    evidenceScore: 8,
    evidenceCodes: ["STORAGE_KEY_READ_TEST"],
    indicators: [
      { type: "campaign", value: fingerprint },
      { type: "url_domain", value: "storage-key-read.example" },
    ],
  };
}

function initializeStore(directory: string): string {
  const store = new EncryptedCommunityAggregateStore(directory);
  store.accept(report());
  const keyPath = join(directory, COMMUNITY_REPORT_KEY_FILE);
  expect(readFileSync(keyPath).length).toBe(COMMUNITY_STORAGE_KEY_BYTES);
  return keyPath;
}

describe("community storage encryption-key read integrity", () => {
  it("preserves normal atomic key creation and subsequent database reads", () => {
    const directory = temporaryDirectory();
    const keyPath = initializeStore(directory);
    expect(existsSync(keyPath)).toBe(true);
    expect(new EncryptedCommunityAggregateStore(directory).stats()).toEqual({
      campaigns: 1,
      warnings: 0,
      confirmed: 0,
    });
  });

  it("rejects a wrong-size key file before it can be accepted for decryption", () => {
    const directory = temporaryDirectory();
    const keyPath = initializeStore(directory);
    writeFileSync(keyPath, Buffer.alloc(COMMUNITY_STORAGE_KEY_BYTES + 1, 7), { mode: 0o600 });

    expect(() => new EncryptedCommunityAggregateStore(directory).stats())
      .toThrow("Community storage encryption key is invalid");
  });

  it("rejects a sparse oversized key file without treating its contents as a key", () => {
    const directory = temporaryDirectory();
    const keyPath = initializeStore(directory);
    writeFileSync(keyPath, "");
    truncateSync(keyPath, 16 * 1024 * 1024);

    expect(() => new EncryptedCommunityAggregateStore(directory).stats())
      .toThrow("Community storage encryption key is invalid");
  });

  it.runIf(process.platform !== "win32")("refuses a POSIX symlink in place of the storage key", () => {
    const directory = temporaryDirectory();
    const keyPath = initializeStore(directory);
    const target = join(directory, "separate-key-target.bin");
    writeFileSync(target, readFileSync(keyPath), { mode: 0o600 });
    unlinkSync(keyPath);
    symlinkSync(target, keyPath);
    expect(lstatSync(keyPath).isSymbolicLink()).toBe(true);

    expect(() => new EncryptedCommunityAggregateStore(directory).stats())
      .toThrow("Community storage encryption key could not be opened safely");
  });

  it("locks same-descriptor size validation before key-byte allocation and keeps the wx race contract", () => {
    const source = readFileSync(join(process.cwd(), "src/community/aggregateStore.ts"), "utf8");
    const generated = source.indexOf("const generated = randomBytes(COMMUNITY_STORAGE_KEY_BYTES)");
    const exclusiveCreate = source.indexOf('writeFileSync(this.keyPath, generated, { mode: 0o600, flag: "wx" })');
    const raceHandling = source.indexOf('code !== "EEXIST"');
    const open = source.indexOf("openSync(this.keyPath, constants.O_RDONLY | noFollow)");
    const stat = source.indexOf("fstatSync(descriptor)", open);
    const exactSize = source.indexOf("stat.size !== COMMUNITY_STORAGE_KEY_BYTES", stat);
    const read = source.indexOf("readFileSync(descriptor)", exactSize);
    const zeroGenerated = source.indexOf("generated.fill(0)", generated);

    expect(generated).toBeGreaterThan(0);
    expect(exclusiveCreate).toBeGreaterThan(generated);
    expect(raceHandling).toBeGreaterThan(exclusiveCreate);
    expect(zeroGenerated).toBeGreaterThan(raceHandling);
    expect(open).toBeGreaterThan(zeroGenerated);
    expect(stat).toBeGreaterThan(open);
    expect(exactSize).toBeGreaterThan(stat);
    expect(read).toBeGreaterThan(exactSize);
  });
});
