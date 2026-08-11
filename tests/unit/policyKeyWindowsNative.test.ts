import { randomUUID } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createDefaultPersonalPolicyRepository,
  EncryptedFilePolicyRepository,
  policyAccountKey,
} from "../../server/src/api/policyPersistence.js";
import type { CredentialReference } from "../../server/src/security/credentialVault.js";
import {
  PowerShellWindowsCredentialBridge,
  WindowsCredentialManagerVault,
} from "../../server/src/security/windowsCredentialManagerVault.js";

const POLICY_KEY_REFERENCE: CredentialReference = {
  id: "personal-policy-encryption-key-v1",
  kind: "local-encryption-key",
};
const temporaryDirectories: string[] = [];

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-policy-native-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("Windows native personal-policy key custody", () => {
  it.skipIf(process.platform !== "win32")(
    "migrates a real legacy policy key through Credential Manager without losing encrypted policy state",
    async () => {
      const directory = temporaryDirectory();
      const key = Buffer.alloc(32, 41);
      const accountKey = policyAccountKey({ provider: "gmail", mode: "fixture" });
      const legacy = new EncryptedFilePolicyRepository(directory, key);
      legacy.save(accountKey, {
        blockedSenders: ["blocked@example.com"],
        blockedDomains: [],
        trustedSenders: [],
        approvedExceptions: [],
        unsubscribedActions: [],
        reportedCampaigns: [],
      });
      writeFileSync(join(directory, "personal-policy.key"), key, { mode: 0o600 });

      const nativeBridge = new PowerShellWindowsCredentialBridge();
      const targetNamespace = `test-${randomUUID()}`;
      const vault = new WindowsCredentialManagerVault({
        invoke(request) {
          return nativeBridge.invoke({
            ...request,
            target: `${request.target}/${targetNamespace}`,
          });
        },
      });
      try {
        const migrated = await createDefaultPersonalPolicyRepository({
          dataDirectory: directory,
          credentialVault: vault,
          platform: "win32",
        });
        expect(migrated.load(accountKey).blockedSenders).toEqual(["blocked@example.com"]);
        expect(existsSync(join(directory, "personal-policy.key"))).toBe(false);
        const protectedSecret = await vault.read(POLICY_KEY_REFERENCE);
        expect(protectedSecret).not.toBeNull();
        expect(Buffer.from(protectedSecret!, "base64")).toEqual(key);
      } finally {
        await vault.delete(POLICY_KEY_REFERENCE);
      }
    },
    30_000,
  );
});
