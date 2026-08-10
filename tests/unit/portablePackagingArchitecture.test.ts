import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(process.cwd(), "..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("portable release packaging architecture", () => {
  it("builds from the lockfile production closure and the exact Node 22 runtime", () => {
    const rootPackage = JSON.parse(read("package.json"));
    const builder = read("scripts/release/build-portable.mjs");
    const library = read("scripts/release/portable-package-lib.mjs");

    expect(rootPackage.scripts).toMatchObject({
      "package:portable": expect.any(String),
      "verify:package": expect.any(String),
      "package:verify": expect.any(String),
    });
    expect(builder).toContain("productionPackagePaths(lockfile)");
    expect(builder).toContain("copyRegularFile(process.execPath");
    expect(builder).toContain('Number(process.versions.node.split(".")[0]) !== 22');
    expect(builder).toContain("assertCleanReleaseTree(root)");
    expect(library).toContain('metadata?.dev !== true && metadata?.link !== true');
    expect(library).toContain('entry.name === "node_modules"');
    expect(library).toContain("Portable package sources must not contain symlinks");
    expect(library).not.toContain("fetch(");
    expect(read("server/package.json")).toContain('"@googleapis/gmail"');
    expect(read("server/package.json")).not.toContain('"googleapis"');
  });

  it("uses a canonical SHA-256 inventory and bundled-runtime launch smoke", () => {
    const library = read("scripts/release/portable-package-lib.mjs");
    const verifier = read("scripts/release/verify-portable.mjs");
    const gate = read("scripts/engineering/run-gate.mjs");

    expect(library).toContain('createHash("sha256")');
    expect(library).toContain("NORMALIZED_MTIME");
    expect(library).toContain("releaseId(manifest)");
    expect(library).toContain("MAX_PORTABLE_PACKAGE_BYTES = 256 * 1024 * 1024");
    expect(library).toContain("artifactBytes: manifest.artifactBytes");
    expect(verifier).toContain("JSON.stringify(actualFiles) !== JSON.stringify(manifest.files)");
    expect(verifier).toContain('manifest.productionPackages.includes("googleapis")');
    expect(verifier).toContain("actualArtifactBytes !== manifest.artifactBytes");
    expect(verifier).toContain('spawn(runtime, ["--version"]');
    expect(verifier).toContain("Portable package did not become ready");
    expect(verifier).toContain("development-only dependencies");
    expect(verifier).toContain("background-protection\\.enc\\.json");
    expect(gate).toContain('"portable-package"');
    expect(gate).toContain('"package:verify"');
  });

  it("publishes one verified host-targeted artifact on every CI platform", () => {
    const workflow = read(".github/workflows/verify.yml");
    const ignore = read(".gitignore");

    expect(workflow).toContain("Upload verified portable package");
    expect(workflow).toContain("email-shield-portable-${{ runner.os }}-${{ runner.arch }}");
    expect(workflow).toContain("artifacts/release/");
    expect(ignore).toContain("artifacts/release/");
  });
});
