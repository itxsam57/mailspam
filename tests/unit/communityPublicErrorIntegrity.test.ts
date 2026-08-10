import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  CommunityReportCapacityError,
  CommunityReportRateLimitError,
} from "../../server/src/community/errors.js";
import { CommunityNetwork } from "../../server/src/community/network.js";
import { createCommunityServiceServer } from "../../server/src/community/server.js";
import { COMMUNITY_REPORT_DATABASE_FILE } from "../../server/src/community/storageFiles.js";
import type { CommunityReportSubmission } from "../../server/src/community/types.js";

const servers: Server[] = [];
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-community-public-error-"));
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

function report(seed = "a"): CommunityReportSubmission {
  const fingerprint = seed.repeat(64).slice(0, 64).replace(/[^a-f0-9]/g, "a");
  return {
    schemaVersion: 1,
    reporterProof: "b".repeat(64),
    campaignFingerprint: fingerprint,
    reportedAt: new Date().toISOString(),
    verdict: "high_risk",
    evidenceScore: 8,
    evidenceCodes: ["PUBLIC_ERROR_TEST"],
    indicators: [
      { type: "campaign", value: fingerprint },
      { type: "url_domain", value: "public-error.example" },
    ],
  };
}

async function expectJsonError(response: Response, status: number, code: string): Promise<void> {
  expect(response.status).toBe(status);
  expect(response.headers.get("content-type")).toContain("application/json");
  expect(response.headers.get("cache-control")).toBe("no-store");
  expect(await response.json()).toEqual({ error: code });
}

describe("dedicated community public error boundary", () => {
  it("returns stable JSON for malformed and oversized JSON instead of Express diagnostics", async () => {
    const base = await start(new CommunityNetwork({ dataDirectory: temporaryDirectory(), serverEnabled: true }));

    await expectJsonError(await fetch(`${base}/api/community/v1/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: '{"broken":',
    }), 400, "invalid_json");

    await expectJsonError(await fetch(`${base}/api/community/v1/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ padding: "x".repeat(70_000) }),
    }), 413, "request_too_large");
  });

  it("maps invalid reports without echoing field-level validation details", async () => {
    const base = await start(new CommunityNetwork({ dataDirectory: temporaryDirectory(), serverEnabled: true }));
    const response = await fetch(`${base}/api/community/v1/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ schemaVersion: 1, reporterProof: "attacker-controlled-secret" }),
    });
    await expectJsonError(response, 400, "invalid_report");
  });

  it("rejects malformed runtime report field types before aggregate persistence", async () => {
    const network = new CommunityNetwork({ dataDirectory: temporaryDirectory(), serverEnabled: true });
    const base = await start(network);
    const valid = report();
    const malformed: unknown[] = [
      { ...valid, verdict: "definitely-not-a-verdict" },
      { ...valid, evidenceScore: "8" },
      { ...valid, evidenceCodes: "PUBLIC_ERROR_TEST" },
      { ...valid, evidenceCodes: ["valid-but-lowercase"] },
      { ...valid, indicators: [{ type: "campaign", value: "c".repeat(64) }] },
      { ...valid, indicators: [{ type: "url_domain", value: 123 }] },
    ];

    for (const body of malformed) {
      await expectJsonError(await fetch(`${base}/api/community/v1/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      }), 400, "invalid_report");
    }

    const info = await (await fetch(`${base}/api/community/v1/public-key`)).json() as {
      stats: { campaigns: number; warnings: number; confirmed: number };
    };
    expect(info.stats).toEqual({ campaigns: 0, warnings: 0, confirmed: 0 });
  });

  it("keeps disabled service and typed operational failures generic", async () => {
    const disabled = new CommunityNetwork({ dataDirectory: temporaryDirectory(), serverEnabled: false });
    const disabledBase = await start(disabled);
    await expectJsonError(await fetch(`${disabledBase}/api/community/v1/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(report()),
    }), 503, "service_unavailable");
    await expectJsonError(await fetch(`${disabledBase}/api/community/v1/public-key`), 503, "service_unavailable");

    const limited = new CommunityNetwork({ dataDirectory: temporaryDirectory(), serverEnabled: true });
    limited.acceptExternalReport = () => { throw new CommunityReportRateLimitError(); };
    const limitedBase = await start(limited);
    await expectJsonError(await fetch(`${limitedBase}/api/community/v1/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(report()),
    }), 429, "rate_limited");

    const full = new CommunityNetwork({ dataDirectory: temporaryDirectory(), serverEnabled: true });
    full.acceptExternalReport = () => { throw new CommunityReportCapacityError(); };
    const fullBase = await start(full);
    await expectJsonError(await fetch(`${fullBase}/api/community/v1/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(report()),
    }), 503, "service_unavailable");
  });

  it("does not leak corrupt storage details from any public operational route", async () => {
    const directory = temporaryDirectory();
    const network = new CommunityNetwork({ dataDirectory: directory, serverEnabled: true });
    network.acceptExternalReport(report());
    const base = await start(network);
    const secretMarker = "TOP-SECRET-INTERNAL-MARKER";
    writeFileSync(
      join(directory, COMMUNITY_REPORT_DATABASE_FILE),
      `not-encrypted-json-${secretMarker}-${directory}`,
      { mode: 0o600 },
    );

    const requests = [
      fetch(`${base}/api/community/v1/status`),
      fetch(`${base}/api/community/v1/feed`),
      fetch(`${base}/api/community/v1/public-key`),
      fetch(`${base}/api/community/v1/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(report("c")),
      }),
    ];
    for (const response of await Promise.all(requests)) {
      expect(response.status).toBe(503);
      expect(response.headers.get("cache-control")).toBe("no-store");
      const text = await response.text();
      expect(text).toBe('{"error":"service_unavailable"}');
      expect(text).not.toContain(secretMarker);
      expect(text).not.toContain(directory);
      expect(text.toLowerCase()).not.toContain("decrypt");
      expect(text.toLowerCase()).not.toContain("stack");
      expect(text).not.toContain("Error:");
    }
  });

  it("sanitizes unexpected route exceptions and unknown paths", async () => {
    const network = new CommunityNetwork({ dataDirectory: temporaryDirectory(), serverEnabled: true });
    network.publicInfo = () => { throw new Error("/private/path signing-key decrypt failed"); };
    const base = await start(network);

    await expectJsonError(await fetch(`${base}/api/community/v1/status`), 503, "service_unavailable");
    await expectJsonError(await fetch(`${base}/does-not-exist`), 404, "not_found");
  });
});
