import { basename, dirname, join } from "node:path";
import { readBoundedUtf8File } from "../util/localFileIntegrity.js";

const MAX_RELEASE_MANIFEST_BYTES = 4 * 1024 * 1024;
const VERSION_PATTERN = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const RELEASE_ID_PATTERN = /^[a-f0-9]{64}$/;
const COMMIT_PATTERN = /^[a-f0-9]{40}$/;

export interface RuntimeReleaseIdentity {
  version: string;
  release: string;
  source: "portable_manifest" | "portable_manifest_unverified" | "development";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function developmentIdentity(environment: NodeJS.ProcessEnv): RuntimeReleaseIdentity {
  const version = String(environment.npm_package_version ?? "").trim();
  const release = String(environment.EMAIL_SHIELD_RELEASE_ID ?? "").trim();
  return {
    version: VERSION_PATTERN.test(version) ? version : "unknown",
    release: RELEASE_ID_PATTERN.test(release) ? release : "development",
    source: "development",
  };
}

/**
 * Resolves consumer-visible release identity from the immutable portable
 * manifest when Email Shield is running through its bundled runtime. Source
 * and developer runs retain the existing environment fallback. A portable
 * runtime with missing/corrupt identity metadata is reported as unverified;
 * it is never mislabeled as a development build.
 */
export function resolveRuntimeReleaseIdentity(
  runtimeExecutablePath = process.execPath,
  environment: NodeJS.ProcessEnv = process.env,
): RuntimeReleaseIdentity {
  const runtimeDirectory = dirname(runtimeExecutablePath);
  if (basename(runtimeDirectory).toLowerCase() !== "runtime") return developmentIdentity(environment);

  const expectedRuntimeName = process.platform === "win32" ? "node.exe" : "node";
  if (basename(runtimeExecutablePath).toLowerCase() !== expectedRuntimeName) {
    return { version: "unknown", release: "unverified_portable", source: "portable_manifest_unverified" };
  }

  try {
    const manifestPath = join(dirname(runtimeDirectory), "release-manifest.json");
    const raw = readBoundedUtf8File(manifestPath, {
      description: "Portable release manifest",
      minBytes: 2,
      maxBytes: MAX_RELEASE_MANIFEST_BYTES,
    });
    const manifest: unknown = JSON.parse(raw);
    if (!isRecord(manifest)
      || manifest.schemaVersion !== 1
      || manifest.product !== "Email Shield"
      || typeof manifest.version !== "string"
      || !VERSION_PATTERN.test(manifest.version)
      || typeof manifest.releaseId !== "string"
      || !RELEASE_ID_PATTERN.test(manifest.releaseId)
      || typeof manifest.commit !== "string"
      || !COMMIT_PATTERN.test(manifest.commit)
      || manifest.platform !== process.platform
      || manifest.architecture !== process.arch
      || manifest.nodeVersion !== process.versions.node
      || manifest.entrypoint !== "app/server/dist/index.js") {
      throw new Error("Portable release manifest identity is invalid.");
    }
    return { version: manifest.version, release: manifest.releaseId, source: "portable_manifest" };
  } catch {
    return { version: "unknown", release: "unverified_portable", source: "portable_manifest_unverified" };
  }
}
