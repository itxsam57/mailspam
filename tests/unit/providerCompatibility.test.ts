import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  PROVIDER_CAPABILITIES,
  PROVIDER_CAPABILITY_SCHEMA_VERSION,
  providerCapabilitySnapshot,
} from "../../server/src/adapters/providerCapabilities.js";

const root = join(import.meta.dirname, "../..");

describe("versioned provider compatibility contract", () => {
  it("requires the identical scan/action/core surface from every provider", () => {
    const snapshot = providerCapabilitySnapshot();
    expect(PROVIDER_CAPABILITY_SCHEMA_VERSION).toBe(1);
    expect(snapshot.map((entry) => entry.provider)).toEqual(["gmail", "icloud", "outlook", "yahoo", "imap"]);
    for (const entry of snapshot) {
      expect(entry.fixtureParity).toBe(true);
      expect(Object.values(entry.capabilities).every(Boolean)).toBe(true);
      expect(entry.capabilities).toEqual(PROVIDER_CAPABILITIES.gmail.capabilities);
    }
  });

  it("matches the reviewed v1 release snapshot exactly", () => {
    const expected = JSON.parse(readFileSync(join(root, "fixtures/provider-compatibility/v1/capabilities.json"), "utf8"));
    expect({ schemaVersion: 1, providers: providerCapabilitySnapshot() }).toEqual(expected);
  });
});
