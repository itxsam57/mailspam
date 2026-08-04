import { afterEach, describe, expect, it } from "vitest";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  EncryptedFilePolicyRepository,
  policyAccountKey,
} from "../../server/src/api/policyPersistence.js";

const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-policy-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

describe("encrypted local personal policy persistence", () => {
  it("restores rules after a new repository instance without storing plaintext values", () => {
    const directory = temporaryDirectory();
    const accountKey = policyAccountKey({
      provider: "icloud",
      mode: "live",
      credentials: { user: "Usama@iCloud.com", appPassword: "must-not-be-written" },
    });
    const first = new EncryptedFilePolicyRepository(directory);
    first.save(accountKey, {
      blockedSenders: ["blocked@example.com"],
      blockedDomains: ["example.net"],
      trustedSenders: [],
      approvedExceptions: [],
    });

    const encryptedText = readFileSync(join(directory, "personal-policies.enc.json"), "utf8");
    expect(encryptedText).not.toContain("blocked@example.com");
    expect(encryptedText).not.toContain("example.net");
    expect(encryptedText).not.toContain("must-not-be-written");
    expect(readFileSync(join(directory, "personal-policy.key"))).toHaveLength(32);

    const second = new EncryptedFilePolicyRepository(directory);
    expect(second.load(accountKey)).toEqual({
      blockedSenders: ["blocked@example.com"],
      blockedDomains: ["example.net"],
      trustedSenders: [],
      approvedExceptions: [],
    });
  });

  it("uses a stable normalized mailbox key that does not depend on the app password", () => {
    const first = policyAccountKey({
      provider: "icloud",
      mode: "live",
      credentials: { user: "User.Name@iCloud.com", appPassword: "old-password" },
    });
    const reconnected = policyAccountKey({
      provider: "icloud",
      mode: "live",
      credentials: { user: " user.name@icloud.com ", appPassword: "new-password" },
    });
    const differentMailbox = policyAccountKey({
      provider: "icloud",
      mode: "live",
      credentials: { user: "other@icloud.com", appPassword: "new-password" },
    });

    expect(reconnected).toBe(first);
    expect(differentMailbox).not.toBe(first);
    expect(first).toMatch(/^[a-f0-9]{64}$/);
  });

  it("fails visibly instead of silently discarding a corrupted encrypted database", () => {
    const directory = temporaryDirectory();
    const repository = new EncryptedFilePolicyRepository(directory);
    const accountKey = policyAccountKey({ provider: "icloud", mode: "fixture" });
    repository.save(accountKey, {
      blockedSenders: ["blocked@example.com"],
      blockedDomains: [],
      trustedSenders: [],
      approvedExceptions: [],
    });

    writeFileSync(join(directory, "personal-policies.enc.json"), "{\"version\":1,\"broken\":true}");
    expect(() => new EncryptedFilePolicyRepository(directory).load(accountKey))
      .toThrow("Encrypted local personal policies could not be read");
  });

  it("sanitizes duplicate and malformed values before encryption", () => {
    const directory = temporaryDirectory();
    const repository = new EncryptedFilePolicyRepository(directory);
    const accountKey = policyAccountKey({ provider: "yahoo", mode: "fixture" });
    repository.save(accountKey, {
      blockedSenders: [" A@Example.com ", "a@example.com", ""],
      blockedDomains: ["Example.com", "example.com"],
      trustedSenders: [],
      approvedExceptions: [],
    });

    expect(repository.load(accountKey)).toEqual({
      blockedSenders: ["a@example.com"],
      blockedDomains: ["example.com"],
      trustedSenders: [],
      approvedExceptions: [],
    });
  });
});
