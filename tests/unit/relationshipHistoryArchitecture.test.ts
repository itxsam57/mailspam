import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const read = (path: string) => readFileSync(resolve(root, path), "utf8");

describe("relationship history architecture", () => {
  it("keeps relationship observations and HMAC material out of every browser script", () => {
    const webDirectory = resolve(root, "web");
    const browserSource = readdirSync(webDirectory)
      .filter((name) => name.endsWith(".js"))
      .map((name) => readFileSync(resolve(webDirectory, name), "utf8"))
      .join("\n");

    for (const forbidden of [
      "relationshipObservations",
      "seenMessageKeys",
      "relationshipIdentityKey",
      "relationship-history-encryption-key-v1",
      "relationshipHistory.indexKey",
    ]) {
      expect(browserSource).not.toContain(forbidden);
    }
  });

  it("requires the server browser-reduction boundary to remove relationship observations", () => {
    const scanStream = read("server/src/api/scanStream.ts");
    expect(scanStream).toContain('"cursor" | "checkpoint" | "relationshipObservations"');
    expect(scanStream).toContain("relationshipObservations: _relationshipObservations");
    expect(scanStream).toContain("defaultRelationshipHistoryRepository.merge");

    const relationshipCommit = scanStream.indexOf("defaultRelationshipHistoryRepository.merge");
    const checkpointCommit = scanStream.indexOf("if (!saveRecord())", relationshipCommit);
    expect(relationshipCommit).toBeGreaterThanOrEqual(0);
    expect(checkpointCommit).toBeGreaterThan(relationshipCommit);
  });

  it("initializes encrypted relationship history before the desktop server starts", () => {
    const index = read("server/src/index.ts");
    const initialize = index.indexOf("await initializeDefaultRelationshipHistoryRepository()");
    const listen = index.indexOf("app.listen(");
    expect(initialize).toBeGreaterThanOrEqual(0);
    expect(listen).toBeGreaterThan(initialize);
  });

  it("never turns established history into a global first-contact bypass", () => {
    const relationshipHistory = read("server/src/engine/relationshipHistory.ts");
    expect(relationshipHistory).not.toMatch(/isFirstContact\s*=\s*false/);
    expect(relationshipHistory).toContain("Established history");

    const relationshipLayer = read("server/src/engine/layers/relationshipContext.ts");
    expect(relationshipLayer).toContain("ESTABLISHED_LOCAL_SENDER_HISTORY");
    expect(relationshipLayer).toContain("scoreContribution: 0");
  });
});
