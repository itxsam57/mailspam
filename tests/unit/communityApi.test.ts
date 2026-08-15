import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "../../server/src/api/server.js";
import { USER_REPORTED_SCAM_CODE } from "../../server/src/community/feedback.js";
import { CommunityNetwork } from "../../server/src/community/network.js";
import { verifyCommunityFeed } from "../../server/src/community/signing.js";
import type { CommunityReportSubmission, SignedCommunityFeed } from "../../server/src/community/types.js";

const servers: Server[] = [];
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-community-api-"));
  directories.push(directory);
  return directory;
}

async function start(network: CommunityNetwork): Promise<string> {
  const server = createServer({ community: network }).listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("listening", () => resolve());
    server.once("error", reject);
  });
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

function report(reporterDigit: string): CommunityReportSubmission {
  const fingerprint = "a".repeat(64);
  return {
    schemaVersion: 1,
    reporterProof: reporterDigit.repeat(64),
    campaignFingerprint: fingerprint,
    reportedAt: new Date().toISOString(),
    verdict: "high_risk",
    evidenceScore: 8,
    evidenceCodes: [USER_REPORTED_SCAM_CODE, "UNSOLICITED_ADULT_SITE_CAMPAIGN", "REPLY_TO_MISMATCH"],
    indicators: [
      { type: "campaign", value: fingerprint },
      { type: "sender", value: "scammer@direct.example" },
      { type: "reply_to_domain", value: "reply-scam.example" },
      { type: "url_domain", value: "redirect-scam.example" },
    ],
  };
}

async function json(response: Response): Promise<any> {
  return await response.json();
}

describe("community service HTTP API", () => {
  it("keeps report ingestion, feed publishing, and public key disabled on a normal client instance", async () => {
    const network = new CommunityNetwork({ dataDirectory: temporaryDirectory(), serverEnabled: false });
    const base = await start(network);

    const status = await fetch(`${base}/api/community/v1/status`);
    expect(status.status).toBe(200);
    expect(await json(status)).toMatchObject({ aggregationServerEnabled: false, clientEnabled: true });

    const submission = await fetch(`${base}/api/community/v1/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(report("1")),
    });
    expect(submission.status).toBe(404);
    expect(await json(submission)).toMatchObject({ error: expect.stringContaining("disabled") });

    expect((await fetch(`${base}/api/community/v1/feed`)).status).toBe(404);
    expect((await fetch(`${base}/api/community/v1/public-key`)).status).toBe(404);
  });

  it("accepts independent explicit reports, deduplicates one reporter, and publishes only an unconfirmed warning feed", async () => {
    const network = new CommunityNetwork({ dataDirectory: temporaryDirectory(), serverEnabled: true });
    const base = await start(network);

    const publicResponse = await fetch(`${base}/api/community/v1/public-key`);
    expect(publicResponse.status).toBe(200);
    const publicInfo = await json(publicResponse);
    expect(publicInfo).toMatchObject({ enabled: true, keyId: expect.any(String), publicKey: expect.stringContaining("BEGIN PUBLIC KEY") });

    for (const reporter of ["1", "2", "3"]) {
      const response = await fetch(`${base}/api/community/v1/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(report(reporter)),
      });
      expect(response.status).toBe(200);
      expect(await json(response)).toMatchObject({
        accepted: true,
        duplicate: false,
        independentReporters: Number(reporter),
        status: reporter === "3" ? "warning" : "candidate",
      });
    }

    const duplicateResponse = await fetch(`${base}/api/community/v1/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(report("3")),
    });
    expect(duplicateResponse.status).toBe(200);
    expect(await json(duplicateResponse)).toMatchObject({ duplicate: true, independentReporters: 3, status: "warning" });

    const feedResponse = await fetch(`${base}/api/community/v1/feed`);
    expect(feedResponse.status).toBe(200);
    const document = await json(feedResponse) as SignedCommunityFeed;
    const payload = verifyCommunityFeed(document, [publicInfo.publicKey]);
    expect(payload).not.toBeNull();
    expect(payload!.entries).toContainEqual(expect.objectContaining({
      type: "campaign",
      value: "a".repeat(64),
      confirmedThreat: false,
      independentReports: 3,
    }));
  });

  it("never lets report ingestion alone publish a Confirmed Threat", async () => {
    const network = new CommunityNetwork({ dataDirectory: temporaryDirectory(), serverEnabled: true });
    const base = await start(network);

    for (const reporter of ["1", "2", "3", "4", "5"]) {
      const response = await fetch(`${base}/api/community/v1/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(report(reporter)),
      });
      expect(response.status).toBe(200);
    }

    const publicInfo = await json(await fetch(`${base}/api/community/v1/public-key`));
    const document = await json(await fetch(`${base}/api/community/v1/feed`)) as SignedCommunityFeed;
    const payload = verifyCommunityFeed(document, [publicInfo.publicKey]);
    expect(payload).not.toBeNull();
    expect(publicInfo.stats).toEqual({ campaigns: 1, warnings: 1, confirmed: 0 });
    expect(payload!.entries.length).toBeGreaterThan(0);
    expect(payload!.entries.every((entry) => entry.type === "identity" || entry.confirmedThreat === false)).toBe(true);
  });

  it("rejects oversized or invalid report payloads without storing them", async () => {
    const network = new CommunityNetwork({ dataDirectory: temporaryDirectory(), serverEnabled: true });
    const base = await start(network);

    const invalid = await fetch(`${base}/api/community/v1/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ schemaVersion: 1, reporterProof: "not-valid" }),
    });
    expect(invalid.status).toBe(400);

    const oversized = await fetch(`${base}/api/community/v1/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ padding: "x".repeat(70_000) }),
    });
    expect(oversized.status).toBe(413);

    const info = await json(await fetch(`${base}/api/community/v1/public-key`));
    expect(info.stats).toEqual({ campaigns: 0, warnings: 0, confirmed: 0 });
  });
});
