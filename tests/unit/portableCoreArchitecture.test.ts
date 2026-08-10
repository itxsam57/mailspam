import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("portable shared-core architecture", () => {
  it("has a versioned bounded contract and a blocking transitive dependency check", () => {
    const core = read("server/src/core/portableCore.ts");
    const workflow = read("server/src/workflows/scanWorkflows.ts");
    const checker = read("scripts/engineering/check-portable-core.mjs");
    const gate = read("scripts/engineering/run-gate.mjs");

    expect(core).toContain("PORTABLE_CORE_SCHEMA_VERSION = 1");
    expect(core).toContain("MAX_PORTABLE_CORE_REQUEST_BYTES = 4 * 1024 * 1024");
    expect(core).toContain("assertPortableCoreRequest(input)");
    expect(core).not.toMatch(/from ["']node:/);
    expect(workflow).toContain("scanMessageThroughPortableCore");
    expect(workflow).not.toContain("scanMessage(envelope, deps)");
    expect(checker).toContain("Portable core dependency boundary passed");
    expect(checker).toContain("forbiddenPathSegments");
    expect(gate).toContain('"portable-core"');
    expect(gate).toContain('"check:core"');
    expect(gate).toContain('"core-vectors"');
    expect(read("fixtures/core-conformance/v1/README.md")).toContain("complete bounded request");
  });

  it("uses platform-neutral hashing and IP parsing on the core dependency path", () => {
    expect(read("server/src/core/sha256.ts")).not.toContain("node:");
    expect(read("server/src/community/fingerprint.ts")).toContain("sha256Hex");
    expect(read("server/src/community/fingerprint.ts")).not.toContain("node:crypto");
    expect(read("server/src/workflows/messageReview.ts")).toContain("sha256Hex");
    expect(read("server/src/workflows/messageReview.ts")).not.toContain("node:crypto");
    expect(read("server/src/util/domainRelation.ts")).not.toContain("node:net");
  });
});
