import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CommunityNetwork } from "../../server/src/community/network.js";
import {
  authorizedMetricsRequest,
  CommunityDiagnosticEmitter,
  CommunityOperationalMetrics,
  configuredMetricsToken,
  createJsonLineCommunityDiagnosticSink,
  emitCommunityDiagnostic,
  type CommunityDiagnosticEvent,
} from "../../server/src/community/operationalMetrics.js";
import { createCommunityServiceServer } from "../../server/src/community/server.js";
import type { CommunityReportSubmission } from "../../server/src/community/types.js";

const servers: Server[] = [];
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function directory(): string {
  const value = mkdtempSync(join(tmpdir(), "email-shield-community-metrics-"));
  directories.push(value);
  return value;
}

async function start(
  network: CommunityNetwork,
  options: Parameters<typeof createCommunityServiceServer>[1] = {},
): Promise<string> {
  const server = createCommunityServiceServer(network, options).listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

function report(): CommunityReportSubmission {
  const campaignFingerprint = "a".repeat(64);
  return {
    schemaVersion: 1,
    reporterProof: "b".repeat(64),
    campaignFingerprint,
    reportedAt: new Date().toISOString(),
    verdict: "high_risk",
    evidenceScore: 8,
    evidenceCodes: ["METRICS_TEST"],
    indicators: [
      { type: "campaign", value: campaignFingerprint },
      { type: "url_domain", value: "sensitive-destination.example" },
    ],
  };
}

async function submit(base: string, body: unknown): Promise<Response> {
  return fetch(`${base}/api/community/v1/report`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("privacy-safe community operational metrics", () => {
  it("keeps the scrape endpoint disabled unless a strong token is configured", async () => {
    const base = await start(new CommunityNetwork({ dataDirectory: directory(), serverEnabled: true }), {
      metricsToken: null,
    });

    const response = await fetch(`${base}/metrics`);

    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "not_found" });
    expect(() => configuredMetricsToken("too-short")).toThrow("between 32 and 4096 bytes");
    expect(() => configuredMetricsToken("x".repeat(4_097))).toThrow("between 32 and 4096 bytes");
    expect(configuredMetricsToken(" ")).toBeNull();
  });

  it("uses exact bearer-token comparison and records auth failures without logging the token", async () => {
    const token = "metrics-token-0123456789-abcdef-strong";
    const events: CommunityDiagnosticEvent[] = [];
    const base = await start(new CommunityNetwork({ dataDirectory: directory(), serverEnabled: true }), {
      metricsToken: token,
      diagnosticSink: (event) => events.push(event),
    });

    expect(authorizedMetricsRequest(`Bearer ${token}`, token)).toBe(true);
    expect(authorizedMetricsRequest(`Bearer ${token}x`, token)).toBe(false);
    expect(authorizedMetricsRequest(undefined, token)).toBe(false);
    const response = await fetch(`${base}/metrics`, { headers: { Authorization: "Bearer wrong-token" } });

    expect(response.status).toBe(401);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(events).toContainEqual(expect.objectContaining({ event: "metrics_auth_failed", severity: "warning" }));
    expect(JSON.stringify(events)).not.toContain("wrong-token");
    expect(JSON.stringify(events)).not.toContain(token);
  });

  it("exports fixed-label aggregate request, report, readiness and abuse metrics only", async () => {
    const token = "metrics-token-0123456789-abcdef-strong";
    const network = new CommunityNetwork({ dataDirectory: directory(), serverEnabled: true });
    const base = await start(network, { metricsToken: token });
    const submission = report();

    expect((await submit(base, submission)).status).toBe(200);
    expect((await submit(base, submission)).status).toBe(200);
    expect((await submit(base, { reporterProof: "private-reporter-value" })).status).toBe(400);
    expect((await fetch(`${base}/health`)).status).toBe(200);
    const response = await fetch(`${base}/metrics`, { headers: { Authorization: `Bearer ${token}` } });
    const text = await response.text();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/plain");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(text).toContain('email_shield_community_reports_total{outcome="accepted"} 1');
    expect(text).toContain('email_shield_community_reports_total{outcome="duplicate"} 1');
    expect(text).toContain('email_shield_community_reports_total{outcome="invalid"} 1');
    expect(text).toContain('email_shield_community_requests_total{route="report",result="2xx"} 2');
    expect(text).toContain('email_shield_community_requests_total{route="report",result="4xx"} 1');
    expect(text).toContain("email_shield_community_ready 1");
    expect(text).toContain('email_shield_community_campaigns{state="all"} 1');
    for (const forbidden of [
      submission.reporterProof,
      submission.campaignFingerprint,
      "sensitive-destination.example",
      "private-reporter-value",
      token,
    ]) expect(text).not.toContain(forbidden);
  });

  it("emits one bounded JSON object with no attacker-controlled diagnostic fields", () => {
    let now = 1_000;
    const metrics = new CommunityOperationalMetrics(() => now);
    const lines: string[] = [];
    const sink = createJsonLineCommunityDiagnosticSink((line) => lines.push(line));

    emitCommunityDiagnostic(metrics, sink, "rate_limited", "warning", () => now);
    now = 2_000;
    metrics.beginRequest();
    metrics.finishRequest("report", 429, 12);

    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]!)).toEqual({
      schemaVersion: 1,
      timestamp: new Date(1_000).toISOString(),
      component: "email-shield-community",
      severity: "warning",
      event: "rate_limited",
    });
    const snapshot = metrics.snapshot();
    expect(snapshot).toMatchObject({
      uptimeSeconds: 1,
      activeRequests: 0,
      reportOutcomes: { rate_limited: 0 },
      diagnostics: { rate_limited: 1 },
    });
    expect(snapshot.requests["report:4xx"]).toBe(1);
  });

  it("counts every diagnostic while bounding JSON-line emission per fixed event", () => {
    let now = 10_000;
    const metrics = new CommunityOperationalMetrics(() => now);
    const events: CommunityDiagnosticEvent[] = [];
    const emitter = new CommunityDiagnosticEmitter(metrics, (event) => events.push(event), () => now, 100);

    emitter.emit("metrics_auth_failed");
    now += 50;
    emitter.emit("metrics_auth_failed");
    emitter.emit("rate_limited");
    now += 51;
    emitter.emit("metrics_auth_failed");

    expect(events.map((event) => event.event)).toEqual([
      "metrics_auth_failed",
      "rate_limited",
      "metrics_auth_failed",
    ]);
    expect(metrics.snapshot().diagnostics).toMatchObject({
      metrics_auth_failed: 3,
      rate_limited: 1,
    });
  });
});
