import { chmodSync, existsSync, lstatSync, mkdtempSync, readFileSync, rmSync, symlinkSync, truncateSync, unlinkSync, writeFileSync } from "node:fs";
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

  it.runIf(process.platform !== "win32")("refuses a POSIX storage key readable by group or other users", () => {
    const directory = temporaryDirectory();
    const keyPath = initializeStore(directory);
    chmodSync(keyPath, 0o644);

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
      .toThrow("Community storage encryption key is invalid");
  });

  it("locks the shared descriptor-bound reader before key-byte allocation and keeps the wx race contract", () => {
    const aggregateSource = readFileSync(join(process.cwd(), "src/community/aggregateStore.ts"), "utf8");
    const readerSource = readFileSync(join(process.cwd(), "src/util/localFileIntegrity.ts"), "utf8");
    const generated = aggregateSource.indexOf("const generated = randomBytes(COMMUNITY_STORAGE_KEY_BYTES)");
    const exclusiveCreate = aggregateSource.indexOf('writeFileSync(this.keyPath, generated, { mode: 0o600, flag: "wx" })');
    const raceHandling = aggregateSource.indexOf('code !== "EEXIST"');
    const zeroGenerated = aggregateSource.indexOf("generated.fill(0)", generated);
    const boundedRead = aggregateSource.indexOf("readBoundedRegularFile(this.keyPath", zeroGenerated);

    const open = readerSource.indexOf("openSync(path, constants.O_RDONLY | noFollow)");
    const stat = readerSource.indexOf("const initial = fstatSync(descriptor)", open);
    const allocation = readerSource.indexOf("Buffer.allocUnsafe(initial.size)", stat);
    const exactRead = readerSource.indexOf("readSync(descriptor, content", allocation);
    const overflowProbe = readerSource.indexOf("readSync(descriptor, overflowProbe", exactRead);
    const finalStat = readerSource.indexOf("const final = fstatSync(descriptor)", overflowProbe);

    expect(generated).toBeGreaterThan(0);
    expect(exclusiveCreate).toBeGreaterThan(generated);
    expect(raceHandling).toBeGreaterThan(exclusiveCreate);
    expect(zeroGenerated).toBeGreaterThan(raceHandling);
    expect(boundedRead).toBeGreaterThan(zeroGenerated);
    expect(open).toBeGreaterThan(0);
    expect(stat).toBeGreaterThan(open);
    expect(allocation).toBeGreaterThan(stat);
    expect(exactRead).toBeGreaterThan(allocation);
    expect(overflowProbe).toBeGreaterThan(exactRead);
    expect(finalStat).toBeGreaterThan(overflowProbe);
  });
});
