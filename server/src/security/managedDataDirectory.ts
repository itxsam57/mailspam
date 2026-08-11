import { existsSync, lstatSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

export const EMAIL_SHIELD_DATA_MARKER_FILE = ".email-shield-data.json";
const MARKER = Object.freeze({
  schemaVersion: 1,
  product: "Email Shield",
  managedDirectory: true,
  purpose: "data",
});

function validMarker(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return Object.keys(record).sort().join(",") === "managedDirectory,product,purpose,schemaVersion"
    && record.schemaVersion === 1
    && record.product === "Email Shield"
    && record.managedDirectory === true
    && record.purpose === "data";
}

/**
 * Marks only the dedicated Email Shield data directory. The guarded release
 * uninstaller requires this exact marker before an explicit --purge-data can
 * remove local state, preventing a broad or mistyped path from being erased.
 */
export function ensureManagedDataDirectory(dataDirectory: string): void {
  const markerPath = join(dataDirectory, EMAIL_SHIELD_DATA_MARKER_FILE);
  mkdirSync(dataDirectory, { recursive: true, mode: 0o700 });
  if (existsSync(markerPath)) {
    const state = lstatSync(markerPath);
    if (!state.isFile() || state.isSymbolicLink() || state.size <= 0 || state.size > 4_096) {
      throw new Error("Email Shield data-directory marker is invalid.");
    }
    try {
      if (!validMarker(JSON.parse(readFileSync(markerPath, "utf8")))) throw new Error();
      return;
    } catch {
      throw new Error("Email Shield data-directory marker is invalid.");
    }
  }
  const temporary = join(dirname(markerPath), `.${EMAIL_SHIELD_DATA_MARKER_FILE}.${process.pid}.tmp`);
  try {
    writeFileSync(temporary, `${JSON.stringify(MARKER, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
    renameSync(temporary, markerPath);
  } finally {
    if (existsSync(temporary)) rmSync(temporary, { force: true });
  }
}
