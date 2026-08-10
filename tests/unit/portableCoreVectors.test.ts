import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { evaluatePortableCore } from "../../server/src/core/portableCore.js";

interface VectorBundle {
  formatVersion: number;
  portableCoreSchemaVersion: number;
  vectors: Array<{ id: string; request: unknown; expectedResponse: unknown }>;
}

const path = join(import.meta.dirname, "../../fixtures/core-conformance/v1/vectors.json");
const raw = readFileSync(path, "utf8");
const bundle = JSON.parse(raw) as VectorBundle;

describe("committed portable-core conformance vectors", () => {
  it("replays exact responses for five providers and adversarial precedence cases", () => {
    expect(bundle).toMatchObject({ formatVersion: 1, portableCoreSchemaVersion: 1 });
    expect(bundle.vectors.map((vector) => vector.id)).toEqual([
      "provider-gmail-credential-phishing",
      "provider-icloud-credential-phishing",
      "provider-outlook-credential-phishing",
      "provider-yahoo-credential-phishing",
      "provider-imap-credential-phishing",
      "adversarial-verified-feed-unavailable",
      "adversarial-personal-block-precedence",
    ]);
    for (const vector of bundle.vectors) {
      expect(evaluatePortableCore(vector.request), vector.id).toEqual(vector.expectedResponse);
    }
  });

  it("contains synthetic bounded inputs without bridge credentials or unconsumed thread identifiers", () => {
    expect(Buffer.byteLength(raw, "utf8")).toBeLessThan(128 * 1024);
    expect(raw).not.toContain('"credentials"');
    expect(raw).not.toContain('"refreshToken"');
    expect(raw).not.toContain('"appPassword"');
    expect(raw).not.toContain('"pendingThreadReferences"');
  });
});
