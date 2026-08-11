import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  EMAIL_SHIELD_DATA_MARKER_FILE,
  ensureManagedDataDirectory,
} from "../../server/src/security/managedDataDirectory.js";

const roots: string[] = [];
afterEach(() => {
  while (roots.length) rmSync(roots.pop()!, { recursive: true, force: true });
});

function root(): string {
  const value = mkdtempSync(join(tmpdir(), "email-shield-data-marker-"));
  roots.push(value);
  return value;
}

describe("managed desktop data-directory marker", () => {
  it("creates and then validates the exact purge-authorization marker", () => {
    const data = join(root(), "data");
    ensureManagedDataDirectory(data);
    const marker = JSON.parse(readFileSync(join(data, EMAIL_SHIELD_DATA_MARKER_FILE), "utf8"));
    expect(marker).toEqual({ schemaVersion: 1, product: "Email Shield", managedDirectory: true, purpose: "data" });
    expect(() => ensureManagedDataDirectory(data)).not.toThrow();
  });

  it("rejects malformed and symlinked marker files", () => {
    const malformed = join(root(), "malformed");
    mkdirSync(malformed);
    writeFileSync(join(malformed, EMAIL_SHIELD_DATA_MARKER_FILE), "{}");
    expect(() => ensureManagedDataDirectory(malformed)).toThrow(/invalid/);

    const linked = join(root(), "linked");
    mkdirSync(linked);
    const target = join(root(), "target.json");
    writeFileSync(target, "{}");
    symlinkSync(target, join(linked, EMAIL_SHIELD_DATA_MARKER_FILE));
    expect(() => ensureManagedDataDirectory(linked)).toThrow(/invalid/);
    expect(existsSync(target)).toBe(true);
  });
});
