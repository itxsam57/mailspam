import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const source = readFileSync(join(root, "web/scam-check.js"), "utf8");

describe("Scam Check Link destination result rendering", () => {
  it("renders the explicit destination inspection result separately from the local scam verdict", () => {
    expect(source).toContain("destinationAnalysis");
    expect(source).toContain("Destination inspected");
    expect(source).toContain("Destination inspection unavailable");
    expect(source).toContain("Credential trap detected");
    expect(source).toContain("Malware destination detected");
  });

  it("does not describe a benign destination inspection as proof that a message or site is safe", () => {
    expect(source).toContain("No credential trap or malware was found in the inspected destination content");
    expect(source).toContain("This does not prove the site or message is safe");
  });
});
