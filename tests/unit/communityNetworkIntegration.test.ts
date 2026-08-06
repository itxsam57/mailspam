import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer } from "../../server/src/api/server.js";
import { CommunityNetwork } from "../../server/src/community/network.js";
import type { CommunityReportContext } from "../../server/src/community/types.js";

const servers: Server[] = [];
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function directory(label: string): string {
  const value = mkdtempSync(join(tmpdir(), `email-shield-${label}-`));
  directories.push(value);
  return value;
}

async function start(network: CommunityNetwork): Promise<string> {
  const server = createServer({ community: network }).listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

const campaignFingerprint = "f".repeat(64);
const context: CommunityReportContext = {
  campaignFingerprint,
  indicators: [
    { type: "campaign", value: campaignFingerprint },
    { type: "sender", value: "rotating-scammer@example.test" },
    { type: "reply_to_domain", value: "reply-scam.example" },
    { type: "url_domain", value: "redirect-scam.example" },
  ],
  evidenceCodes: ["UNSOLICITED_ADULT_SITE_CAMPAIGN", "REPLY_TO_MISMATCH"],
  evidenceScore: 8,
  verdict: "high_risk",
};

describe("cross-instance community shield", () => {
  it("aggregates three independent client proofs and distributes a verified warning to another client", async () => {
    const central = new CommunityNetwork({
      dataDirectory: directory("central"),
      serverEnabled: true,
    });
    const baseUrl = await start(central);
    const publicInfo = central.publicInfo();

    for (let index = 1; index <= 3; index++) {
      const client = new CommunityNetwork({
        dataDirectory: directory(`client-${index}`),
        remoteUrl: baseUrl,
        trustedPublicKeys: [publicInfo.publicKey],
      });
      const receipt = await client.submit(context, index.toString(16).padStart(64, "0"));
      expect(receipt.delivery).toBe("remote_shared");
      expect(receipt.queued).toBe(false);
      expect(receipt.independentReporters).toBe(index);
      expect(receipt.status).toBe(index === 3 ? "warning" : "candidate");
    }

    const protectedClient = new CommunityNetwork({
      dataDirectory: directory("protected-client"),
      remoteUrl: baseUrl,
      trustedPublicKeys: [publicInfo.publicKey],
    });
    await protectedClient.refreshFeed();
    const entries = protectedClient.getVerifiedEntries();
    expect(entries).not.toBeNull();
    expect(entries).toContainEqual(expect.objectContaining({
      type: "campaign",
      value: campaignFingerprint,
      confirmedThreat: false,
      independentReports: 3,
    }));
  });

  it("labels an unreachable configured service as queued remote, not shared success", async () => {
    const client = new CommunityNetwork({
      dataDirectory: directory("offline-client"),
      remoteUrl: "http://127.0.0.1:1",
      trustedPublicKeys: [],
    });
    const receipt = await client.submit(context, "a".repeat(64));
    expect(receipt).toMatchObject({
      accepted: true,
      queued: true,
      delivery: "queued_remote",
      status: "candidate",
    });
    expect(client.pendingReports()).toBe(1);
  });

  it("labels no-remote embedded aggregation as local-only", async () => {
    const client = new CommunityNetwork({
      dataDirectory: directory("embedded-client"),
      serverEnabled: false,
      remoteUrl: null,
    });
    const receipt = await client.submit(context, "b".repeat(64));
    expect(receipt).toMatchObject({
      accepted: true,
      queued: false,
      delivery: "embedded_local",
      independentReporters: 1,
      status: "candidate",
    });
  });
});
