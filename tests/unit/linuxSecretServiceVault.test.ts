import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { CredentialReference } from "../../server/src/security/credentialVault.js";
import {
  LinuxSecretServiceVault,
  SecretToolLinuxCredentialBridge,
  type LinuxSecretServiceBridge,
  type LinuxSecretServiceBridgeRequest,
  type LinuxSecretServiceBridgeResponse,
} from "../../server/src/security/linuxSecretServiceVault.js";

const reference: CredentialReference = {
  id: "linux-test-ref-7f50c828-1d83-4d6b-a680-57c1b530ea81",
  kind: "imap-app-password",
};

class MemoryLinuxBridge implements LinuxSecretServiceBridge {
  readonly records = new Map<string, string>();
  readonly requests: LinuxSecretServiceBridgeRequest[] = [];

  async invoke(request: LinuxSecretServiceBridgeRequest): Promise<LinuxSecretServiceBridgeResponse> {
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

describe("Linux Secret Service vault", () => {
  it("round-trips through the shared vault contract with opaque lookup metadata", async () => {
    const bridge = new MemoryLinuxBridge();
    const vault = new LinuxSecretServiceVault(bridge);
    const secret = "linux-app-password-value";

    expect(vault.capabilities()).toMatchObject({
      backend: "linux-secret-service",
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

  it("uses secret-tool stdin for writes and never places the secret in argv", () => {
    const source = readFileSync(
      new URL("../../server/src/security/linuxSecretServiceVault.ts", import.meta.url),
      "utf8",
    );
    const runner = readFileSync(
      new URL("../../server/src/security/nativeCredentialCommand.ts", import.meta.url),
      "utf8",
    );

    expect(source).toContain('"store",');
    expect(source).toContain("stdin: request.secret");
    expect(source).not.toContain("request.secret,");
    expect(source).not.toContain("args: [request.secret");
    expect(runner).toContain("shell: false");
    expect(runner).toContain("child.stderr.resume()");
  });

  it("does not preserve secret-bearing bridge error text", async () => {
    const secret = "never-log-this-linux-secret";
    const vault = new LinuxSecretServiceVault({
      async invoke(request) {
        throw new Error(`failed around ${request.secret}`);
      },
    });

    try {
      await vault.write(reference, secret);
      throw new Error("Expected Linux vault write to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(Error);
      expect((error as Error).message).not.toContain(secret);
      expect(String(error)).not.toContain(secret);
    }
  });
});

if (process.platform === "linux" && process.env.EMAIL_SHIELD_TEST_SECRET_SERVICE === "1") {
  describe("Linux Secret Service native integration", () => {
    it("stores, retrieves and deletes an ephemeral real Secret Service item", async () => {
      const vault = new LinuxSecretServiceVault(new SecretToolLinuxCredentialBridge());
      expect(vault.capabilities().available).toBe(true);
      const liveReference: CredentialReference = {
        id: `ci-linux-${randomUUID()}`,
        kind: "local-encryption-key",
      };
      const secret = `email-shield-linux-ci-${randomUUID()}`;

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
