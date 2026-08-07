import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  CredentialVaultError,
  credentialTargetName,
  type CredentialReference,
  UnsupportedCredentialVault,
  validateCredentialSecret,
} from "../../server/src/security/credentialVault.js";
import { createCredentialVault } from "../../server/src/security/credentialVaultFactory.js";
import {
  PowerShellWindowsCredentialBridge,
  type WindowsCredentialBridge,
  type WindowsCredentialBridgeRequest,
  type WindowsCredentialBridgeResponse,
  WindowsCredentialManagerVault,
} from "../../server/src/security/windowsCredentialManagerVault.js";

const reference: CredentialReference = {
  id: "account-ref-7f50c828-1d83-4d6b-a680-57c1b530ea81",
  kind: "imap-app-password",
};

class MemoryBridge implements WindowsCredentialBridge {
  readonly records = new Map<string, string>();
  readonly requests: WindowsCredentialBridgeRequest[] = [];

  async invoke(request: WindowsCredentialBridgeRequest): Promise<WindowsCredentialBridgeResponse> {
    this.requests.push({ ...request });
    switch (request.operation) {
      case "write":
        this.records.set(request.target, request.secret ?? "");
        return { ok: true };
      case "read": {
        const secret = this.records.get(request.target);
        return secret === undefined
          ? { ok: true, found: false }
          : { ok: true, found: true, secret };
      }
      case "delete":
        this.records.delete(request.target);
        return { ok: true };
    }
  }
}

describe("credential vault contract", () => {
  it("derives opaque Windows target metadata without mailbox or reference leakage", () => {
    const target = credentialTargetName(reference);
    expect(target).toMatch(/^EmailShield\/[a-f0-9]{64}$/);
    expect(target).not.toContain(reference.id);
    expect(target).not.toContain(reference.kind);
    expect(credentialTargetName(reference)).toBe(target);
  });

  it("rejects empty and oversized secrets instead of truncating them", () => {
    expect(() => validateCredentialSecret("")).toThrow(CredentialVaultError);
    expect(() => validateCredentialSecret("x".repeat(2_561))).toThrow(/exceeds/i);
    expect(() => validateCredentialSecret("valid-secret")).not.toThrow();
  });

  it("round-trips and deletes through the Windows vault contract", async () => {
    const bridge = new MemoryBridge();
    const vault = new WindowsCredentialManagerVault(bridge);
    const secret = "app-password-example-value";

    await vault.write(reference, secret);
    expect(await vault.read(reference)).toBe(secret);
    await vault.delete(reference);
    expect(await vault.read(reference)).toBeNull();

    expect(bridge.requests.map((request) => request.operation)).toEqual(["write", "read", "delete", "read"]);
    for (const request of bridge.requests) {
      expect(request.target).toBe(credentialTargetName(reference));
      expect(request.target).not.toContain(reference.id);
    }
  });

  it("rejects malformed credential payloads read from a backend", async () => {
    const emptyBridge: WindowsCredentialBridge = {
      async invoke() { return { ok: true, found: true, secret: "" }; },
    };
    await expect(new WindowsCredentialManagerVault(emptyBridge).read(reference))
      .rejects.toMatchObject({ code: "VAULT_OPERATION_FAILED" });

    const oversizedBridge: WindowsCredentialBridge = {
      async invoke() { return { ok: true, found: true, secret: "x".repeat(2_561) }; },
    };
    await expect(new WindowsCredentialManagerVault(oversizedBridge).read(reference))
      .rejects.toMatchObject({ code: "INVALID_SECRET" });
  });

  it("fails closed on unsupported platforms and never substitutes plaintext storage", async () => {
    const vault = new UnsupportedCredentialVault("test-platform");
    expect(vault.capabilities()).toEqual({
      backend: "unsupported:test-platform",
      available: false,
      persistent: false,
      userBound: false,
      hardwareBacked: false,
      applicationBound: false,
    });
    await expect(vault.write(reference, "secret-value")).rejects.toMatchObject({ code: "VAULT_UNAVAILABLE" });
    await expect(vault.read(reference)).rejects.toMatchObject({ code: "VAULT_UNAVAILABLE" });
    await expect(vault.delete(reference)).rejects.toMatchObject({ code: "VAULT_UNAVAILABLE" });
  });

  it("does not keep a bridge failure's secret-bearing error text in the public vault error", async () => {
    const secret = "must-never-appear-in-error";
    const bridge: WindowsCredentialBridge = {
      async invoke(request) {
        throw new Error(`bridge failed while handling ${request.secret}`);
      },
    };
    const vault = new WindowsCredentialManagerVault(bridge);

    try {
      await vault.write(reference, secret);
      throw new Error("Expected write to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(CredentialVaultError);
      expect((error as Error).message).not.toContain(secret);
      expect(String(error)).not.toContain(secret);
    }
  });

  it("keeps runtime secrets off the PowerShell command line and disables shell execution", () => {
    const source = readFileSync(
      new URL("../../server/src/security/windowsCredentialManagerVault.ts", import.meta.url),
      "utf8",
    );
    expect(source).toContain('["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedCommand]');
    expect(source).toContain('child.stdin.end(JSON.stringify(request), "utf8")');
    expect(source).not.toContain("shell: true");
    expect(source).toContain("child.stderr.resume()");
  });

  it("uses the real Windows backend only on Windows", () => {
    const linux = createCredentialVault("linux");
    expect(linux.capabilities().available).toBe(false);
    const darwin = createCredentialVault("darwin");
    expect(darwin.capabilities().available).toBe(false);
  });
});

if (process.platform === "win32") {
  describe("Windows Credential Manager integration", () => {
    it("stores, retrieves and securely deletes an ephemeral real credential", async () => {
      const vault = new WindowsCredentialManagerVault(new PowerShellWindowsCredentialBridge());
      const liveReference: CredentialReference = {
        id: `ci-${randomUUID()}`,
        kind: "imap-app-password",
      };
      const secret = `email-shield-ci-${randomUUID()}`;

      try {
        await vault.write(liveReference, secret);
        expect(await vault.read(liveReference)).toBe(secret);
      } finally {
        await vault.delete(liveReference);
      }
      expect(await vault.read(liveReference)).toBeNull();
    }, 20_000);
  });
}
