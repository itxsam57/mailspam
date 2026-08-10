import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = process.cwd();
const host = "127.0.0.1";
const dataDir = mkdtempSync(join(tmpdir(), "email-shield-community-smoke-"));
const metricsToken = "community-smoke-metrics-token-32-bytes-minimum";
let child;
let stdout = "";
let stderr = "";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function freePort() {
  return await new Promise((resolvePort, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, host, () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : null;
      server.close((error) => error ? reject(error) : resolvePort(port));
    });
  });
}

async function waitForReady(baseUrl, timeoutMs = 20_000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    if (child?.exitCode !== null) throw new Error(`Community service exited before readiness with code ${child.exitCode}.\n${stderr}`);
    try {
      const response = await fetch(`${baseUrl}/health`, { signal: AbortSignal.timeout(2_000) });
      if (response.ok) return;
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 150));
  }
  throw new Error(`Community service did not become ready: ${lastError?.message ?? "unknown error"}\n${stderr}`);
}

async function json(response, label) {
  const body = await response.json().catch(() => null);
  assert(response.ok, `${label} failed with HTTP ${response.status}: ${JSON.stringify(body)}`);
  return body;
}

function reporterProof(label) {
  return createHash("sha256").update(`community-smoke:${label}`).digest("hex");
}

function report(label) {
  const campaignFingerprint = "c".repeat(64);
  return {
    schemaVersion: 1,
    reporterProof: reporterProof(label),
    campaignFingerprint,
    reportedAt: new Date().toISOString(),
    verdict: "high_risk",
    evidenceScore: 8,
    evidenceCodes: ["UNSOLICITED_ADULT_SITE_CAMPAIGN", "REPLY_TO_MISMATCH"],
    indicators: [
      { type: "campaign", value: campaignFingerprint },
      { type: "sender", value: "smoke-scammer@example.test" },
      { type: "reply_to_domain", value: "reply-smoke.example" },
      { type: "url_domain", value: "redirect-smoke.example" },
    ],
  };
}

try {
  const port = await freePort();
  assert(Number.isInteger(port), "Could not allocate an isolated community smoke-test port.");
  const baseUrl = `http://${host}:${port}`;

  child = spawn(process.execPath, [resolve(root, "server/dist/communityIndex.js")], {
    cwd: root,
    env: {
      ...process.env,
      HOST: host,
      PORT: String(port),
      EMAIL_SHIELD_DATA_DIR: dataDir,
      EMAIL_SHIELD_COMMUNITY_SERVER: "1",
      EMAIL_SHIELD_COMMUNITY_URL: "",
      EMAIL_SHIELD_COMMUNITY_PRIVATE_KEY: "",
      EMAIL_SHIELD_COMMUNITY_PUBLIC_KEY: "",
      EMAIL_SHIELD_COMMUNITY_PUBLIC_KEYS: "",
      EMAIL_SHIELD_COMMUNITY_METRICS_TOKEN: metricsToken,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });

  await waitForReady(baseUrl);

  const healthResponse = await fetch(`${baseUrl}/health`);
  const health = await json(healthResponse, "Community health");
  assert(
    health.service === "email-shield-community" && health.ready === true && health.signedFeedAvailable === true,
    "Dedicated service health contract was unexpected.",
  );
  assert(healthResponse.headers.get("cache-control") === "no-store", "Community health response was cacheable.");
  assert((await fetch(baseUrl)).status === 404, "Dedicated community service unexpectedly exposed a homepage.");
  assert((await fetch(`${baseUrl}/api/accounts`)).status === 404, "Dedicated community service unexpectedly exposed mailbox account APIs.");
  assert((await fetch(`${baseUrl}/api/dev/test-suite`)).status === 404, "Dedicated community service unexpectedly exposed desktop developer APIs.");

  const publicInfo = await json(await fetch(`${baseUrl}/api/community/v1/public-key`), "Community public key");
  assert(publicInfo.enabled === true, "Community public-key endpoint did not confirm server mode.");
  assert(typeof publicInfo.keyId === "string" && /^[a-f0-9]{24}$/.test(publicInfo.keyId), "Community key ID was invalid.");
  assert(typeof publicInfo.publicKey === "string" && publicInfo.publicKey.includes("BEGIN PUBLIC KEY"), "Community public key was missing.");

  for (const label of ["one", "two", "three"]) {
    const receipt = await json(await fetch(`${baseUrl}/api/community/v1/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(report(label)),
    }), `Community report ${label}`);
    const expectedCount = ["one", "two", "three"].indexOf(label) + 1;
    assert(receipt.accepted === true && receipt.duplicate === false, `Report ${label} was not accepted independently.`);
    assert(receipt.independentReporters === expectedCount, `Report ${label} returned ${receipt.independentReporters} reporters instead of ${expectedCount}.`);
    assert(receipt.status === (expectedCount === 3 ? "warning" : "candidate"), `Report ${label} returned unexpected status ${receipt.status}.`);
  }

  const duplicate = await json(await fetch(`${baseUrl}/api/community/v1/report`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(report("three")),
  }), "Duplicate community report");
  assert(duplicate.duplicate === true && duplicate.independentReporters === 3, "Duplicate reporter was counted more than once.");

  const unauthorizedMetrics = await fetch(`${baseUrl}/metrics`);
  assert(unauthorizedMetrics.status === 401, "Community metrics accepted an unauthenticated scrape.");
  const metricsResponse = await fetch(`${baseUrl}/metrics`, {
    headers: { Authorization: `Bearer ${metricsToken}` },
  });
  const metrics = await metricsResponse.text();
  assert(metricsResponse.ok, `Authenticated community metrics failed with HTTP ${metricsResponse.status}.`);
  assert(metricsResponse.headers.get("cache-control") === "no-store", "Community metrics response was cacheable.");
  assert(metrics.includes('email_shield_community_reports_total{outcome="accepted"} 3'), "Community accepted-report metric was incorrect.");
  assert(metrics.includes('email_shield_community_reports_total{outcome="duplicate"} 1'), "Community duplicate-report metric was incorrect.");
  for (const forbidden of [metricsToken, reporterProof("one"), "redirect-smoke.example"]) {
    assert(!metrics.includes(forbidden), "Community metrics exposed a protected source value.");
  }

  const feedDocument = await json(await fetch(`${baseUrl}/api/community/v1/feed`), "Signed community feed");
  const signingModuleUrl = pathToFileURL(resolve(root, "server/dist/community/signing.js")).href;
  const { inspectCommunityFeed } = await import(signingModuleUrl);
  const verification = inspectCommunityFeed(feedDocument, [publicInfo.publicKey]);
  assert(verification.reason === null && verification.payload, `Compiled signed feed did not verify: ${verification.reason}`);
  assert(verification.payload.entries.some((entry) =>
    entry.type === "campaign" &&
    entry.value === "c".repeat(64) &&
    entry.confirmedThreat === false &&
    entry.independentReports === 3
  ), "Signed warning feed did not contain the expected three-reporter campaign indicator.");

  const tampered = structuredClone(feedDocument);
  tampered.payload.entries.push({
    type: "sender",
    value: "tampered@example.test",
    confirmedThreat: true,
    ruleId: "tampered",
  });
  assert(inspectCommunityFeed(tampered, [publicInfo.publicKey]).reason === "signature_mismatch", "Tampered compiled feed was not rejected as a signature mismatch.");

  console.log(`Dedicated community service smoke passed at ${baseUrl}.`);
  console.log(`Verified warning indicators: ${verification.payload.entries.length}.`);
} catch (error) {
  console.error(`FAIL: ${error.message}`);
  if (stdout.trim()) console.error(`Community stdout:\n${stdout.trim()}`);
  if (stderr.trim()) console.error(`Community stderr:\n${stderr.trim()}`);
  process.exitCode = 1;
} finally {
  if (child && child.exitCode === null) {
    child.kill();
    await new Promise((resolveWait) => {
      const timer = setTimeout(() => {
        if (child.exitCode === null) child.kill("SIGKILL");
        resolveWait();
      }, 2_000);
      child.once("exit", () => {
        clearTimeout(timer);
        resolveWait();
      });
    });
  }
  rmSync(dataDir, { recursive: true, force: true });
}
