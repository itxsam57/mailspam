import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { resolveRuntimeReleaseIdentity } from "../../server/src/api/runtimeReleaseIdentity.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function portableRuntime(manifest: Record<string, unknown>): string {
  const root = mkdtempSync(join(tmpdir(), "email-shield-release-identity-"));
  roots.push(root);
  mkdirSync(join(root, "runtime"), { recursive: true });
  writeFileSync(join(root, "release-manifest.json"), `${JSON.stringify(manifest)}\n`, "utf8");
  return join(root, "runtime", process.platform === "win32" ? "node.exe" : "node");
}

function validManifest(): Record<string, unknown> {
  return {
    schemaVersion: 1,
    product: "Email Shield",
    version: "0.2.0",
    releaseId: "a".repeat(64),
    commit: "b".repeat(40),
    platform: process.platform,
    architecture: process.arch,
    nodeVersion: process.versions.node,
    entrypoint: "app/server/dist/index.js",
  };
}

describe("runtime release identity", () => {
  it("uses the portable manifest identity instead of npm-only environment metadata", () => {
    const runtime = portableRuntime(validManifest());
    expect(resolveRuntimeReleaseIdentity(runtime, {
      npm_package_version: "9.9.9",
      EMAIL_SHIELD_RELEASE_ID: "c".repeat(64),
    })).toEqual({
      version: "0.2.0",
      release: "a".repeat(64),
      source: "portable_manifest",
    });
  });

  it("fails honest when a bundled runtime has malformed or mismatched release metadata", () => {
    for (const manifest of [
      { ...validManifest(), releaseId: "not-a-release-id" },
      { ...validManifest(), platform: process.platform === "win32" ? "linux" : "win32" },
      { ...validManifest(), nodeVersion: "0.0.0" },
    ]) {
      expect(resolveRuntimeReleaseIdentity(portableRuntime(manifest), {})).toEqual({
        version: "unknown",
        release: "unverified_portable",
        source: "portable_manifest_unverified",
      });
    }
  });

  it("keeps the environment fallback only for genuine source/development runtimes", () => {
    const developmentRuntime = join(tmpdir(), process.platform === "win32" ? "node.exe" : "node");
    expect(resolveRuntimeReleaseIdentity(developmentRuntime, { npm_package_version: "0.2.0" })).toEqual({
      version: "0.2.0",
      release: "development",
      source: "development",
    });
  });
});
