import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { CredentialReference } from "../../server/src/security/credentialVault.js";
import {
  MacOSKeychainVault,
  SecurityCliMacOSKeychainBridge,
  type MacOSKeychainBridge,
  type MacOSKeychainBridgeRequest,
  type MacOSKeychainBridgeResponse,
} from "../../server/src/security/macosKeychainVault.js";

const reference: CredentialReference = {
  id: "macos-test-ref-7f50c828-1d83-4d6b-a680-57c1b530ea81",
  kind: "oauth-refresh-token",
};

class MemoryMacBridge implements MacOSKeychainBridge {
  readonly records = new Map<string, string>();
  readonly requests: MacOSKeychainBridgeRequest[] = [];

  async invoke(request: MacOSKeychainBridgeRequest): Promise<MacOSKeychainBridgeResponse> {
    this.requests.push({ ...request });
    if (request.operation === "write") {
      this.records.set(request.target, request.secret ?? "");
      return { ok: true };
    }
    if (request.operation === "read") {
      const secret = this.records.get(request.target);
      return secret === undefined
        ? { ok: true, found: false }
        : { ok: true, found: true, secret };
    }
    this.records.delete(request.target);
    return { ok: true };
  }
}

describe("macOS Keychain vault", () => {
  it("round-trips through the shared vault contract with opaque metadata", async () => {
    const bridge = new MemoryMacBridge();
    const vault = new MacOSKeychainVault(bridge);
    const secret = "macos-refresh-token-value";

    expect(vault.capabilities()).toMatchObject({
      backend: "macos-keychain",
      available: true,
      persistent: true,
      userBound: true,
      hardwareBacked: false,
      applicationBound: false,
    });

    await vault.write(reference, secret);
    expect(await vault.read(reference)).toBe(secret);
    await vault.delete(reference);
    expect(await vault.read(reference)).toBeNull();

    for (const request of bridge.requests) {
      expect(request.target).toMatch(/^EmailShield\/[a-f0-9]{64}$/);
      expect(request.target).not.toContain(reference.id);
      expect(request.target).not.toContain(reference.kind);
    }
  });

  it("keeps write secrets off the macOS security command line", () => {
    const source = readFileSync(
      new URL("../../server/src/security/macosKeychainVault.ts", import.meta.url),
      "utf8",
    );
    const runner = readFileSync(
      new URL("../../server/src/security/nativeCredentialCommand.ts", import.meta.url),
      "utf8",
    );

    expect(source).toContain('"add-generic-password"');
    expect(source).toContain('"-U",');
    expect(source).toContain('"-w",');
    expect(source).toContain('stdin: `${encoded}\\n`');
    expect(source).not.toContain('"-w", encoded');
    expect(source).not.toContain('"-w", request.secret');
    expect(runner).toContain('shell: false');
    expect(runner).toContain('child.stderr.resume()');
    expect(runner).toContain('child.stdin.end(options.stdin, "utf8")');
  });

  it("does not preserve secret-bearing bridge error text", async () => {
    const secret = "never-log-this-macos-secret";
    const vault = new MacOSKeychainVault({
      async invoke(request) {
        throw new Error(`failed around ${request.secret}`);
      },
    });

    await expect(vault.write(reference, secret)).rejects.toSatisfy((error: unknown) => {
      return error instanceof Error && !error.message.includes(secret) && !String(error).includes(secret);
    });
  });
});

if (process.platform === "darwin") {
  describe("macOS Keychain native integration", () => {
    it("stores, retrieves and deletes an ephemeral real Keychain item", async () => {
      const vault = new MacOSKeychainVault(new SecurityCliMacOSKeychainBridge());
      const liveReference: CredentialReference = {
        id: `ci-macos-${randomUUID()}`,
        kind: "local-encryption-key",
      };
      const secret = `email-shield-macos-ci-${randomUUID()}`;

      try {
        await vault.write(liveReference, secret);
        expect(await vault.read(liveReference)).toBe(secret);
      } finally {
        await vault.delete(liveReference);
      }
      expect(await vault.read(liveReference)).toBeNull();
    }, 45_000);
  });
}
