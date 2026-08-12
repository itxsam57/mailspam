import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { AccountPlatformService } from "../../server/src/platform/accountFamilyService.js";
import {
  EncryptedFileAccountPlatformRepository,
  InMemoryAccountPlatformRepository,
  normalizeAccountPlatformState,
} from "../../server/src/platform/accountFamilyPersistence.js";
import type { AccountPlatformRuntime } from "../../server/src/platform/accountFamilyPorts.js";
import type { DevicePublicIdentity } from "../../server/src/platform/accountFamilyTypes.js";

const directories: string[] = [];
afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

class Runtime implements AccountPlatformRuntime {
  private sequence = 0;
  now() { return 1_900_000_000_000; }
  id(prefix: "acct" | "family" | "invite") { return `${prefix}_persist-${++this.sequence}`; }
  secret() { return `persist-secret-${String(++this.sequence).padStart(20, "0")}`; }
}

function identity(): DevicePublicIdentity {
  return {
    algorithm: "ed25519",
    publicKeySpki: Buffer.from("device-public-key-material".repeat(4), "utf8").toString("base64"),
    platform: "desktop",
    label: "Private desktop",
  };
}

describe("account and Family Shield protected persistence", () => {
  it("stores account metadata only inside authenticated ciphertext", () => {
    const memory = new InMemoryAccountPlatformRepository();
    const service = new AccountPlatformService(memory, new Runtime());
    service.createAccount("private.user", identity());

    const directory = mkdtempSync(join(tmpdir(), "email-shield-account-family-"));
    directories.push(directory);
    const key = randomBytes(32);
    const encrypted = new EncryptedFileAccountPlatformRepository(directory, key);
    encrypted.save(memory.load());

    const raw = readFileSync(join(directory, "account-family.enc.json"), "utf8");
    expect(raw).toContain('"algorithm":"aes-256-gcm"');
    expect(raw).not.toContain("private.user");
    expect(raw).not.toContain("Private desktop");
    expect(encrypted.load().accounts[0]?.username).toBe("private.user");
  });

  it("fails closed when ciphertext is modified", () => {
    const memory = new InMemoryAccountPlatformRepository();
    new AccountPlatformService(memory, new Runtime()).createAccount("tamper.user", identity());
    const directory = mkdtempSync(join(tmpdir(), "email-shield-account-family-tamper-"));
    directories.push(directory);
    const encrypted = new EncryptedFileAccountPlatformRepository(directory, randomBytes(32));
    encrypted.save(memory.load());
    const path = join(directory, "account-family.enc.json");
    const envelope = JSON.parse(readFileSync(path, "utf8"));
    envelope.ciphertext = `${String(envelope.ciphertext).slice(0, -4)}AAAA`;
    writeFileSync(path, JSON.stringify(envelope));
    expect(() => encrypted.load()).toThrow(/could not be read/i);
  });

  it("rejects unknown fields instead of silently expanding persistent account schema", () => {
    expect(() => normalizeAccountPlatformState({
      schemaVersion: 1,
      currentAccountId: null,
      accounts: [],
      familyCircles: [],
      mailboxLinks: [],
      rawEmailArchive: [],
    })).toThrow(/unknown fields/i);
  });
});
