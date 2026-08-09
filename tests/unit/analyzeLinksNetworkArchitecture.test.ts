import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

function source(path: string): string {
  return readFileSync(resolve(process.cwd(), path), "utf8");
}

describe("Analyze Links network architecture", () => {
  it("pins sockets to validated DNS addresses instead of using global fetch", () => {
    const hardened = source("src/util/hardenedFetch.ts");

    expect(hardened).toContain("lookup as dnsLookup");
    expect(hardened).toContain("hostname: pinned.address");
    expect(hardened).toContain("servername: isIP(originalHostname) === 0 ? originalHostname : undefined");
    expect(hardened).toContain('Host: target.host');
    expect(hardened).toContain('"Accept-Encoding": "identity"');
    expect(hardened).not.toMatch(/\bfetch\s*\(/);
    expect(hardened).not.toMatch(/^\s*["']?(?:Cookie|Authorization)["']?\s*:/im);
  });

  it("keeps deep-link network access out of automatic mailbox scans", () => {
    const scans = source("src/workflows/scanWorkflows.ts");
    const worker = source("src/workers/scanWorker.ts");
    const analyze = source("src/workflows/analyzeLinks.ts");

    expect(scans).not.toContain("hardenedFetch");
    expect(scans).not.toContain("analyzeLinks(");
    expect(worker).not.toContain("hardenedFetch");
    expect(analyze).toContain("never called automatically during any scan");
  });

  it("wires the production API to hardenedFetch and fails uninspectable content closed", () => {
    const server = source("src/api/server.ts");
    const classifier = source("src/engine/layers/destinationClassification.ts");

    expect(server).toContain('import { hardenedFetch } from "../util/hardenedFetch.js"');
    expect(server).toContain("analyzeLinks(envelope, hardenedFetch)");
    expect(classifier).toContain("it was not treated as benign");
  });
});
