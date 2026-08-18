import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { validateCheckpointManifest } from "../../server/src/diagnostics/checkpointManifest.js";

const root = join(import.meta.dirname, "../..");
const script = join(root, "scripts/engineering/generate-runtime-trace-manifest.mjs");
const temporaryDirectories: string[] = [];

function gitHead(): string {
  return execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
}

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-runtime-manifest-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

describe("EMA-5 exact-build runtime checkpoint manifest", () => {
  it("generates deterministic source ownership for the exact checked-out commit", () => {
    expect(existsSync(script)).toBe(true);
    if (!existsSync(script)) return;

    const output = join(temporaryDirectory(), "runtime-trace-manifest.json");
    execFileSync(process.execPath, [script, "--output", output], {
      cwd: root,
      env: { ...process.env, EMAIL_SHIELD_BUILD_COMMIT: "", GITHUB_SHA: "" },
      stdio: "pipe",
    });

    const head = gitHead();
    const raw = JSON.parse(readFileSync(output, "utf8")) as unknown;
    const manifest = validateCheckpointManifest(raw, { buildId: head });
    expect(manifest).not.toBeNull();
    expect(manifest!.buildId).toBe(head);
    expect(manifest!.checkpoints.length).toBeGreaterThan(0);

    const ids = new Set(manifest!.checkpoints.map((entry) => entry.checkpointId));
    expect(ids).toContain("mailbox.scan.quick.requested");
    expect(ids).toContain("message.report_scam.requested");
    for (const entry of manifest!.checkpoints) {
      expect(entry.sourcePath.startsWith("server/src/") || entry.sourcePath.startsWith("web/")).toBe(true);
      expect(entry.sourcePath).not.toContain("..");
      expect(entry.line).toBeGreaterThan(0);
    }
    expect(JSON.stringify(raw)).not.toContain(root);
  });

  it("rejects an explicit build identity that contradicts the checked-out commit", () => {
    expect(existsSync(script)).toBe(true);
    if (!existsSync(script)) return;
    const output = join(temporaryDirectory(), "runtime-trace-manifest.json");
    const head = gitHead();
    const conflicting = head === "a".repeat(40) ? "b".repeat(40) : "a".repeat(40);
    expect(() => execFileSync(process.execPath, [script, "--output", output], {
      cwd: root,
      env: { ...process.env, EMAIL_SHIELD_BUILD_COMMIT: conflicting },
      stdio: "pipe",
    })).toThrow();
  });
});
