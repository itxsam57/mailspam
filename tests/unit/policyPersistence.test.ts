import { afterEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EncryptedFilePolicyRepository, policyAccountKey } from "../../server/src/api/policyPersistence.js";

const temporaryDirectories: string[] = [];
const policyKey = (seed = 7) => Buffer.alloc(32, seed);

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-policy-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("encrypted local personal policy persistence", () => {
  it("restores account rules without storing plaintext values or a raw key file", () => {
    const directory = temporaryDirectory();
    const accountKey = policyAccountKey({
      provider: "icloud",
      mode: "live",
      credentials: { user: "owner@icloud.com", appPassword: "private-app-password" },
    });
    const messageKey = `message:${"a".repeat(64)}`;
    const campaignFingerprint = "b".repeat(64);
    const key = policyKey();
    const first = new EncryptedFilePolicyRepository(directory, key);
    first.save(accountKey, {
      blockedSenders: ["blocked@example.com"],
      blockedDomains: ["example.net"],
      trustedSenders: ["trusted@example.org"],
      approvedExceptions: [messageKey],
      unsubscribedActions: ["campaign-hash"],
      reportedCampaigns: [campaignFingerprint],
    });

    const encryptedText = readFileSync(join(directory, "personal-policies.enc.json"), "utf8");
    for (const privateValue of [
      "blocked@example.com", "example.net", "trusted@example.org", messageKey,
      "campaign-hash", campaignFingerprint, "private-app-password",
    ]) expect(encryptedText).not.toContain(privateValue);
    expect(existsSync(join(directory, "personal-policy.key"))).toBe(false);

    expect(new EncryptedFilePolicyRepository(directory, key).load(accountKey)).toEqual({
      blockedSenders: ["blocked@example.com"],
      blockedDomains: ["example.net"],
      trustedSenders: ["trusted@example.org"],
      approvedExceptions: [messageKey],
      unsubscribedActions: ["campaign-hash"],
      reportedCampaigns: [campaignFingerprint],
    });
  });

  it("uses a stable normalized mailbox key that does not depend on an app password", () => {
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
    const different = policyAccountKey({
      provider: "icloud",
      mode: "live",
      credentials: { user: "other@icloud.com", appPassword: "new-password" },
    });
    expect(reconnected).toBe(first);
    expect(different).not.toBe(first);
    expect(first).toMatch(/^[a-f0-9]{64}$/);
  });

  it("fails visibly instead of discarding a corrupted encrypted database", () => {
    const directory = temporaryDirectory();
    const key = policyKey(9);
    const repository = new EncryptedFilePolicyRepository(directory, key);
    const accountKey = policyAccountKey({ provider: "icloud", mode: "fixture" });
    repository.save(accountKey, {
      blockedSenders: ["blocked@example.com"], blockedDomains: [], trustedSenders: [],
      approvedExceptions: [], unsubscribedActions: [], reportedCampaigns: [],
    });
    writeFileSync(join(directory, "personal-policies.enc.json"), "{\"version\":1,\"broken\":true}");
    expect(() => new EncryptedFilePolicyRepository(directory, key).load(accountKey))
      .toThrow("Encrypted local personal policies could not be read");
  });

  it("sanitizes duplicate and malformed values before encryption", () => {
    const directory = temporaryDirectory();
    const repository = new EncryptedFilePolicyRepository(directory, policyKey(10));
    const accountKey = policyAccountKey({ provider: "yahoo", mode: "fixture" });
    repository.save(accountKey, {
      blockedSenders: [" A@Example.com ", "a@example.com", ""],
      blockedDomains: ["Example.com", "example.com"],
      trustedSenders: [" Trusted@Example.org ", "trusted@example.org"],
      approvedExceptions: [` MESSAGE:${"B".repeat(64)} `],
      unsubscribedActions: [" Campaign-Key ", "campaign-key"],
      reportedCampaigns: [` ${"C".repeat(64)} `, "not-a-fingerprint"],
    });
    expect(repository.load(accountKey)).toEqual({
      blockedSenders: ["a@example.com"],
      blockedDomains: ["example.com"],
      trustedSenders: ["trusted@example.org"],
      approvedExceptions: [`message:${"b".repeat(64)}`],
      unsubscribedActions: ["campaign-key"],
      reportedCampaigns: ["c".repeat(64)],
    });
  });
});
