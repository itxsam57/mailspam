import type { AddressInfo } from "node:net";
import { createServer, type Server } from "node:http";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CommunityFeedRollbackGuard } from "../../server/src/community/feedRollbackGuard.js";
import { CommunityNetwork } from "../../server/src/community/network.js";
import { CommunityFeedSigner } from "../../server/src/community/signing.js";
import type { CommunityFeedPayload, SignedCommunityFeed } from "../../server/src/community/types.js";

const directories: string[] = [];
const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function directory(label: string): string {
  const value = mkdtempSync(join(tmpdir(), `email-shield-feed-rollback-${label}-`));
  directories.push(value);
  return value;
}

function payload(generatedAt: Date, value: string): CommunityFeedPayload {
  return {
    version: 1,
    generatedAt: generatedAt.toISOString(),
    expiresAt: new Date(generatedAt.getTime() + 60 * 60_000).toISOString(),
    entries: [{
      type: "url_domain",
      value,
      confirmedThreat: true,
      ruleId: `rollback:${value}`,
      independentReports: 5,
    }],
  };
}

async function startFeedServer(current: () => SignedCommunityFeed): Promise<string> {
  const server = createServer((request, response) => {
    if (request.url === "/api/community/v1/feed") {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify(current()));
      return;
    }
    response.writeHead(404).end();
  });
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe("monotonic signed community feed acceptance", () => {
  it("persists the newest generation, rejects rollback/equivocation and allows same-payload key overlap", () => {
    const stateDirectory = directory("guard");
    const firstSigner = new CommunityFeedSigner(directory("signer-one"));
    const nextSigner = new CommunityFeedSigner(directory("signer-two"));
    const generatedAt = new Date("2026-08-11T00:00:00.000Z");
    const acceptedPayload = payload(generatedAt, "accepted.example");
    const accepted = firstSigner.sign(acceptedPayload);
    const guard = new CommunityFeedRollbackGuard(stateDirectory);
    guard.accept(accepted, acceptedPayload);

    const overlap = nextSigner.sign(acceptedPayload);
    guard.accept(overlap, acceptedPayload);

    const olderPayload = payload(new Date(generatedAt.getTime() - 1), "older.example");
    expect(() => new CommunityFeedRollbackGuard(stateDirectory).accept(firstSigner.sign(olderPayload), olderPayload))
      .toThrow("generation is older");

    const conflictingPayload = payload(generatedAt, "equivocation.example");
    expect(() => new CommunityFeedRollbackGuard(stateDirectory).accept(firstSigner.sign(conflictingPayload), conflictingPayload))
      .toThrow("equivocation");

    const encrypted = readFileSync(join(stateDirectory, "community-feed-rollback.enc.json"), "utf8");
    expect(encrypted).not.toContain("accepted.example");
    expect(encrypted).not.toContain(acceptedPayload.generatedAt);
  });

  it("keeps the last accepted feed active when a remote service serves a still-fresh older signed feed", async () => {
    const signer = new CommunityFeedSigner(directory("remote-signer"));
    const now = new Date();
    const olderPayload = payload(new Date(now.getTime() - 60_000), "older.example");
    const newerPayload = payload(now, "newer.example");
    const older = signer.sign(olderPayload);
    const newer = signer.sign(newerPayload);
    let served = newer;
    const remoteUrl = await startFeedServer(() => served);
    const clientDirectory = directory("client");
    const client = new CommunityNetwork({
      dataDirectory: clientDirectory,
      remoteUrl,
      trustedPublicKeys: [signer.publicPem],
    });

    await client.refreshFeed();
    expect(client.getVerifiedEntries()).toContainEqual(expect.objectContaining({ value: "newer.example" }));

    served = older;
    await client.refreshFeed();
    expect(client.getVerifiedEntries()).toContainEqual(expect.objectContaining({ value: "newer.example" }));
    expect(client.getVerifiedEntries()).not.toContainEqual(expect.objectContaining({ value: "older.example" }));
    expect(client.lastRefreshError()).toContain("rollback");

    const restarted = new CommunityNetwork({
      dataDirectory: clientDirectory,
      remoteUrl,
      trustedPublicKeys: [signer.publicPem],
    });
    expect(restarted.getVerifiedEntries()).toContainEqual(expect.objectContaining({ value: "newer.example" }));
    await restarted.refreshFeed();
    expect(restarted.getVerifiedEntries()).toContainEqual(expect.objectContaining({ value: "newer.example" }));
  });
});
