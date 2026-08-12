import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { FileFixtureConnectionPersistence } from "../../server/src/api/fixtureConnectionPersistence.js";
import { InMemoryPolicyRepository } from "../../server/src/api/policyPersistence.js";
import { SessionStore } from "../../server/src/api/sessionStore.js";

describe("fixture connection persistence", () => {
  it("restores only unique provider names and cannot serialize mail or credentials", () => {
    const directory = mkdtempSync(join(tmpdir(), "email-shield-fixtures-"));
    const first = new FileFixtureConnectionPersistence(directory);
    first.remember("gmail");
    first.remember("gmail");
    first.remember("outlook");

    const serialized = readFileSync(join(directory, "fixture-connections.json"), "utf8");
    expect(JSON.parse(serialized)).toEqual({ version: 1, providers: ["gmail", "outlook"] });
    expect(serialized).not.toMatch(/credential|password|message|subject|address|label/i);

    const store = new SessionStore(new InMemoryPolicyRepository());
    new FileFixtureConnectionPersistence(directory).restore(store);
    expect(store.list().map((session) => session.provider).sort()).toEqual(["gmail", "outlook"]);
    expect(store.list().every((session) => session.config.mode === "fixture")).toBe(true);
  });
});
