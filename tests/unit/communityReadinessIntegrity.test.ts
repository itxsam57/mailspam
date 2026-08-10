import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CommunityNetwork } from "../../server/src/community/network.js";
import { createCommunityServiceServer, inspectCommunityServiceReadiness } from "../../server/src/community/server.js";
import { COMMUNITY_REPORT_DATABASE_FILE } from "../../server/src/community/storageFiles.js";
import type { CommunityReportSubmission, SignedCommunityFeed } from "../../server/src/community/types.js";

const servers: Server[] = [];
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-community-readiness-"));
  directories.push(directory);
  return directory;
}

async function start(network: CommunityNetwork): Promise<string> {
  const server = createCommunityServiceServer(network).listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

function report(): CommunityReportSubmission {
  const fingerprint = "a".repeat(64);
  return {
    schemaVersion: 1,
    reporterProof: "b".repeat(64),
    campaignFingerprint: fingerprint,
    reportedAt: new Date().toISOString(),
    verdict: "high_risk",
    evidenceScore: 8,
    evidenceCodes: ["READINESS_TEST"],
    indicators: [
      { type: "campaign", value: fingerprint },
      { type: "url_domain", value: "readiness.example" },
    ],
  };
}

async function body(response: Response): Promise<Record<string, unknown>> {
  return await response.json() as Record<string, unknown>;
}

describe("community service readiness integrity", () => {
  it("reports disabled service mode as unavailable with HTTP 503", async () => {
    const network = new CommunityNetwork({ dataDirectory: temporaryDirectory(), serverEnabled: false });
    const base = await start(network);

    const response = await fetch(`${base}/health`);
    expect(response.status).toBe(503);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await body(response)).toEqual({
      service: "email-shield-community",
      ready: false,
      signedFeedAvailable: false,
    });
  });

  it("reports ready only when the current aggregate can be signed and self-verified", async () => {
    const network = new CommunityNetwork({ dataDirectory: temporaryDirectory(), serverEnabled: true });
    network.acceptExternalReport(report());
    const base = await start(network);

    const response = await fetch(`${base}/health`);
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await body(response)).toEqual({
      service: "email-shield-community",
      ready: true,
      signedFeedAvailable: true,
    });
  });

  it("caches successful readiness briefly instead of rebuilding and signing on every probe", async () => {
    const network = new CommunityNetwork({ dataDirectory: temporaryDirectory(), serverEnabled: true });
    const originalSignedFeed = network.signedFeed.bind(network);
    let signCalls = 0;
    network.signedFeed = () => {
      signCalls++;
      return originalSignedFeed();
    };
    const base = await start(network);

    expect((await fetch(`${base}/health`)).status).toBe(200);
    expect((await fetch(`${base}/health`)).status).toBe(200);
    expect((await fetch(`${base}/health`)).status).toBe(200);
    expect(signCalls).toBe(1);
  });

  it("fails closed when authoritative aggregate state becomes unreadable after startup", async () => {
    const directory = temporaryDirectory();
    const network = new CommunityNetwork({ dataDirectory: directory, serverEnabled: true });
    network.acceptExternalReport(report());
    const base = await start(network);
    writeFileSync(join(directory, COMMUNITY_REPORT_DATABASE_FILE), "not-an-encrypted-community-database", { mode: 0o600 });

    const response = await fetch(`${base}/health`);
    const payload = await body(response);
    expect(response.status).toBe(503);
    expect(payload).toEqual({
      service: "email-shield-community",
      ready: false,
      signedFeedAvailable: false,
    });
    expect(JSON.stringify(payload)).not.toContain(directory);
    expect(JSON.stringify(payload).toLowerCase()).not.toContain("decrypt");
    expect(JSON.stringify(payload).toLowerCase()).not.toContain("key");
  });

  it("does not report a feed as available merely because signing returned a document", () => {
    const network = new CommunityNetwork({ dataDirectory: temporaryDirectory(), serverEnabled: true });
    const valid = network.signedFeed();
    const tampered = structuredClone(valid) as SignedCommunityFeed;
    tampered.payload.entries.push({
      type: "domain",
      value: "tampered.example",
      confirmedThreat: true,
      ruleId: "tampered-readiness",
    });
    network.signedFeed = () => tampered;

    expect(inspectCommunityServiceReadiness(network)).toEqual({
      ready: false,
      signedFeedAvailable: false,
    });
  });
});
