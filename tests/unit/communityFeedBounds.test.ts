import type { AddressInfo } from "node:net";
import { createServer, type RequestListener, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CommunityNetwork } from "../../server/src/community/network.js";
import {
  MAX_COMMUNITY_FEED_ENTRIES,
  MAX_COMMUNITY_FEED_ENTRY_VALUE_CHARS,
  MAX_COMMUNITY_FEED_RESPONSE_BYTES,
  MAX_COMMUNITY_IDENTITY_ALIASES,
  MAX_COMMUNITY_RECEIPT_RESPONSE_BYTES,
} from "../../server/src/community/resourceLimits.js";
import { CommunityFeedSigner, inspectCommunityFeed } from "../../server/src/community/signing.js";
import type {
  CommunityFeedPayload,
  CommunityReportContext,
  SignedCommunityFeed,
} from "../../server/src/community/types.js";

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

function signer(label = "feed-bounds-signer"): CommunityFeedSigner {
  return new CommunityFeedSigner(directory(label));
}

function freshPayload(entries: CommunityFeedPayload["entries"] = []): CommunityFeedPayload {
  const now = new Date();
  return {
    version: 1,
    generatedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 60 * 60_000).toISOString(),
    entries,
  };
}

function dummyDocument(payload: CommunityFeedPayload): SignedCommunityFeed {
  return {
    version: 1,
    payload,
    signature: {
      algorithm: "Ed25519",
      keyId: "a".repeat(24),
      value: Buffer.alloc(64).toString("base64"),
    },
  };
}

async function startServer(handler: RequestListener): Promise<string> {
  const server = createServer(handler);
  servers.push(server);
  server.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

describe("signed community feed semantic bounds", () => {
  it("rejects more than the bounded number of feed entries before trust evaluation", () => {
    const entries = Array.from({ length: MAX_COMMUNITY_FEED_ENTRIES + 1 }, (_, index) => ({
      type: "sender" as const,
      value: `sender-${index}@example.test`,
      confirmedThreat: false,
      ruleId: `rule-${index}`,
    }));
    const result = inspectCommunityFeed(dummyDocument(freshPayload(entries)), [], new Date());
    expect(result).toEqual({ payload: null, reason: "too_many_entries" });
  });

  it("rejects oversized entry values and identity alias fan-out", () => {
    const oversizedValue = inspectCommunityFeed(dummyDocument(freshPayload([{
      type: "sender",
      value: "x".repeat(MAX_COMMUNITY_FEED_ENTRY_VALUE_CHARS + 1),
      confirmedThreat: false,
      ruleId: "oversized-value",
    }])), [], new Date());
    expect(oversizedValue.reason).toBe("invalid_entry");

    const aliases = Array.from({ length: MAX_COMMUNITY_IDENTITY_ALIASES + 1 }, (_, index) => `Alias ${index}`);
    const excessiveAliases = inspectCommunityFeed(dummyDocument(freshPayload([{
      type: "identity",
      value: "Example Identity",
      aliases,
      domains: ["example.test"],
      confirmedThreat: false,
      ruleId: "identity-alias-fanout",
    }])), [], new Date());
    expect(excessiveAliases.reason).toBe("invalid_entry");
  });

  it("requires an exact 64-byte Ed25519 signature encoding", () => {
    const document = dummyDocument(freshPayload());
    document.signature.value = Buffer.alloc(63).toString("base64");
    expect(inspectCommunityFeed(document, [], new Date()).reason).toBe("invalid_signature_encoding");
  });

  it("signs and verifies a normal bounded threat feed", () => {
    const feedSigner = signer();
    const payload = freshPayload([{
      type: "url_domain",
      value: "phishing.example",
      confirmedThreat: true,
      ruleId: "community:bounded-feed",
      independentReports: 5,
    }]);
    const document = feedSigner.sign(payload);
    expect(inspectCommunityFeed(document, [feedSigner.publicPem], new Date()).payload).toEqual(payload);
  });

  it("refuses to sign a document that would exceed the client acquisition boundary", () => {
    const feedSigner = signer("oversized-signer");
    const entries = Array.from({ length: 2_200 }, (_, index) => ({
      type: "sender" as const,
      value: `${index}-${"x".repeat(MAX_COMMUNITY_FEED_ENTRY_VALUE_CHARS - String(index).length - 1)}`,
      confirmedThreat: false,
      ruleId: `large-${index}`,
    }));
    expect(() => feedSigner.sign(freshPayload(entries))).toThrow("bounded signed-document size limit");
  });
});

describe("remote community response byte bounds", () => {
  it("fails closed before reading a feed whose declared size exceeds the limit", async () => {
    const baseUrl = await startServer((req, res) => {
      if (req.url === "/api/community/v1/feed") {
        res.writeHead(200, {
          "Content-Type": "application/json",
          "Content-Length": String(MAX_COMMUNITY_FEED_RESPONSE_BYTES + 1),
        });
        res.end(" ".repeat(MAX_COMMUNITY_FEED_RESPONSE_BYTES + 1));
        return;
      }
      res.writeHead(404).end();
    });
    const client = new CommunityNetwork({
      dataDirectory: directory("declared-oversized-feed"),
      remoteUrl: baseUrl,
      trustedPublicKeys: [],
    });

    await client.refreshFeed();
    expect(client.getVerifiedEntries()).toBeNull();
    expect(client.lastRefreshError()).toContain("bounded JSON limit");
  });

  it("stops a chunked feed once streamed bytes cross the limit", async () => {
    const baseUrl = await startServer((req, res) => {
      if (req.url === "/api/community/v1/feed") {
        res.writeHead(200, { "Content-Type": "application/json", "Transfer-Encoding": "chunked" });
        const chunk = "x".repeat(64 * 1024);
        for (let sent = 0; sent <= MAX_COMMUNITY_FEED_RESPONSE_BYTES; sent += chunk.length) res.write(chunk);
        res.end();
        return;
      }
      res.writeHead(404).end();
    });
    const client = new CommunityNetwork({
      dataDirectory: directory("streamed-oversized-feed"),
      remoteUrl: baseUrl,
      trustedPublicKeys: [],
    });

    await client.refreshFeed();
    expect(client.getVerifiedEntries()).toBeNull();
    expect(client.lastRefreshError()).toContain("bounded JSON limit");
  });

  it("keeps a still-valid verified cache when a later remote feed is oversized", async () => {
    const feedSigner = signer("cache-signer");
    const validDocument = feedSigner.sign(freshPayload([{
      type: "campaign",
      value: "c".repeat(64),
      confirmedThreat: false,
      ruleId: "cache-rule",
      independentReports: 3,
    }]));
    let oversized = false;
    const baseUrl = await startServer((req, res) => {
      if (req.url !== "/api/community/v1/feed") return void res.writeHead(404).end();
      if (!oversized) {
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify(validDocument));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json", "Transfer-Encoding": "chunked" });
      const chunk = "x".repeat(64 * 1024);
      for (let sent = 0; sent <= MAX_COMMUNITY_FEED_RESPONSE_BYTES; sent += chunk.length) res.write(chunk);
      res.end();
    });
    const client = new CommunityNetwork({
      dataDirectory: directory("cached-good-feed"),
      remoteUrl: baseUrl,
      trustedPublicKeys: [feedSigner.publicPem],
    });

    await client.refreshFeed();
    expect(client.getVerifiedEntries()).toHaveLength(1);
    oversized = true;
    await client.refreshFeed();
    expect(client.getVerifiedEntries()).toHaveLength(1);
    expect(client.lastRefreshError()).toContain("bounded JSON limit");
  });

  it("queues a report when the remote receipt exceeds its smaller response limit", async () => {
    const baseUrl = await startServer((req, res) => {
      if (req.url === "/api/community/v1/report") {
        res.writeHead(200, {
          "Content-Type": "application/json",
          "Content-Length": String(MAX_COMMUNITY_RECEIPT_RESPONSE_BYTES + 1),
        });
        res.end(" ".repeat(MAX_COMMUNITY_RECEIPT_RESPONSE_BYTES + 1));
        return;
      }
      res.writeHead(404).end();
    });
    const client = new CommunityNetwork({
      dataDirectory: directory("oversized-receipt"),
      remoteUrl: baseUrl,
      trustedPublicKeys: [],
    });
    const context: CommunityReportContext = {
      campaignFingerprint: "d".repeat(64),
      indicators: [{ type: "campaign", value: "d".repeat(64) }],
      evidenceCodes: ["TEST_EVIDENCE"],
      evidenceScore: 8,
      verdict: "high_risk",
    };

    const receipt = await client.submit(context, "e".repeat(64));
    expect(receipt).toMatchObject({ accepted: true, queued: true, delivery: "queued_remote" });
    expect(client.pendingReports()).toBe(1);
  });
});
