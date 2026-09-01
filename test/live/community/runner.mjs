import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import net from "node:net";
import { execFileSync, spawn } from "node:child_process";
import {
  COMMUNITY_REVIEW_MIN_SPAN_MS,
  EncryptedCommunityAggregateStore,
} from "../../../server/dist/community/aggregateStore.js";
import { verifyCommunityFeed } from "../../../server/dist/community/signing.js";

const root = resolve(process.cwd());
const baseTmp = mkdtempSync(join(tmpdir(), "email-shield-community-live-"));
const dataDir = join(baseTmp, "primary");
const restoredDir = join(baseTmp, "restored");
const rotationDir = join(baseTmp, "rotation");
const backupFile = join(baseTmp, "community-backup.json");
const passphraseFile = join(baseTmp, "backup-passphrase.txt");
const metricsToken = `metrics-${createHash("sha256").update(baseTmp).digest("hex")}`;
const publicCampaign = createHash("sha256").update("email-shield-live-community-public-time-forgery-probe").digest("hex");
const governedCampaign = createHash("sha256").update("email-shield-live-community-governed-campaign").digest("hex");
const reporterProofs = Array.from({ length: 5 }, (_, index) => createHash("sha256").update(`email-shield-live-community-reporter-${index}`).digest("hex"));
let child = null;
let serviceLogs = "";

mkdirSync(dataDir, { recursive: true });
writeFileSync(passphraseFile, "email-shield-live-community-backup-passphrase-2026", { mode: 0o600 });
chmodSync(passphraseFile, 0o600);

function freePort() {
  return new Promise((resolvePort, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      assert(address && typeof address === "object");
      const port = address.port;
      server.close((error) => error ? reject(error) : resolvePort(port));
    });
  });
}

async function waitForReady(baseUrl) {
  let lastError = null;
  for (let attempt = 0; attempt < 80; attempt++) {
    try {
      const response = await fetch(`${baseUrl}/health`, { signal: AbortSignal.timeout(1_500) });
      if (response.ok) return;
      lastError = new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 150));
  }
  throw new Error(`Community service did not become ready: ${lastError?.message ?? "unknown"}\n${serviceLogs}`);
}

async function startService(directory, extraEnv = {}) {
  assert.equal(child, null, "Community service already running");
  const port = await freePort();
  serviceLogs = "";
  child = spawn(process.execPath, [join(root, "server/dist/communityIndex.js")], {
    cwd: root,
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      PORT: String(port),
      EMAIL_SHIELD_DATA_DIR: directory,
      EMAIL_SHIELD_COMMUNITY_SERVER: "1",
      EMAIL_SHIELD_COMMUNITY_URL: "",
      EMAIL_SHIELD_COMMUNITY_PRIVATE_KEY: "",
      EMAIL_SHIELD_COMMUNITY_PUBLIC_KEY: "",
      EMAIL_SHIELD_COMMUNITY_PUBLIC_KEYS: "",
      EMAIL_SHIELD_COMMUNITY_METRICS_TOKEN: metricsToken,
      ...extraEnv,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { serviceLogs += chunk; });
  child.stderr.on("data", (chunk) => { serviceLogs += chunk; });
  const baseUrl = `http://127.0.0.1:${port}`;
  await waitForReady(baseUrl);
  return baseUrl;
}

async function stopService() {
  if (!child) return;
  const active = child;
  child = null;
  if (active.exitCode === null) active.kill("SIGTERM");
  await Promise.race([
    new Promise((resolveExit) => active.once("exit", resolveExit)),
    new Promise((resolveWait) => setTimeout(resolveWait, 3_000)),
  ]);
  if (active.exitCode === null) active.kill("SIGKILL");
}

async function json(response, label) {
  const body = await response.json().catch(() => null);
  assert(response.ok, `${label} failed with HTTP ${response.status}: ${JSON.stringify(body)}`);
  return body;
}

function runOps(args, env = {}) {
  const stdout = execFileSync(process.execPath, [join(root, "server/dist/communityOps.js"), ...args], {
    cwd: root,
    env: { ...process.env, ...env },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
  return stdout ? JSON.parse(stdout) : null;
}

function report(campaignFingerprint, index, reportedAt) {
  return {
    schemaVersion: 1,
    reporterProof: reporterProofs[index],
    campaignFingerprint,
    reportedAt,
    verdict: "high_risk",
    evidenceScore: 8,
    evidenceCodes: ["USER_REPORTED_SCAM", "REPLY_TO_MISMATCH"],
    indicators: [
      { type: "campaign", value: campaignFingerprint },
      { type: "sender", value: "live-community-controlled@example.test" },
      { type: "reply_to_domain", value: "controlled-reply.example" },
    ],
  };
}

function spreadTimes(referenceMs = Date.now()) {
  return [25, 24, 23, 22, 1].map((hoursAgo) => new Date(referenceMs - hoursAgo * 60 * 60_000).toISOString());
}

function candidateMatches(item, campaignFingerprint) {
  return item.campaignFingerprint === campaignFingerprint &&
    item.independentReporters === 5 &&
    item.strongReporters === 5 &&
    item.distinctUtcDays >= 2 &&
    item.observedSpanMs >= COMMUNITY_REVIEW_MIN_SPAN_MS;
}

function seedServerAuthoritativeReviewCandidate(directory) {
  const times = spreadTimes();
  let authoritativeNow = new Date(times[0]);
  const store = new EncryptedCommunityAggregateStore(directory, undefined, {
    now: () => new Date(authoritativeNow),
  });
  try {
    for (let index = 0; index < 5; index++) {
      authoritativeNow = new Date(times[index]);
      const receipt = store.accept(report(governedCampaign, index, times[index]));
      assert.equal(receipt.accepted, true);
      assert.equal(receipt.duplicate, false);
      assert.notEqual(receipt.status, "confirmed");
    }
    const candidates = store.listReviewCandidates();
    assert(candidates.some((item) => candidateMatches(item, governedCampaign)), "Server-authoritative controlled clock did not create the expected review candidate");
  } finally {
    store.close();
  }
}

function assertConfirmedFeed(document, publicKey, campaignFingerprint = governedCampaign) {
  const payload = verifyCommunityFeed(document, [publicKey]);
  assert(payload, "Signed Community feed failed verification with the published key");
  const entry = payload.entries.find((item) => item.type === "campaign" && item.value === campaignFingerprint);
  assert(entry && entry.confirmedThreat === true && entry.independentReports >= 5, "Confirmed governed campaign missing from verified feed");
  return payload;
}

try {
  let baseUrl = await startService(dataDir);

  const health = await json(await fetch(`${baseUrl}/health`), "Community health");
  assert.equal(health.service, "email-shield-community");
  assert.equal(health.ready, true);
  assert.equal(health.signedFeedAvailable, true);
  assert.equal((await fetch(baseUrl)).status, 404);
  assert.equal((await fetch(`${baseUrl}/api/accounts`)).status, 404);
  assert.equal((await fetch(`${baseUrl}/api/dev/test-suite`)).status, 404);
  console.log("LIVE-C01 PASS — shipping Community-only service is ready and consumer/mailbox/developer surfaces remain absent");

  const publicInfo = await json(await fetch(`${baseUrl}/api/community/v1/public-key`), "Community public key");
  assert.equal(publicInfo.enabled, true);
  assert.match(publicInfo.keyId, /^[a-f0-9]{24}$/);
  assert.match(publicInfo.publicKey, /BEGIN PUBLIC KEY/);
  const initialKeyId = publicInfo.keyId;
  const initialPublicKey = publicInfo.publicKey;
  const initialFeed = await json(await fetch(`${baseUrl}/api/community/v1/feed`), "Initial signed feed");
  assert(verifyCommunityFeed(initialFeed, [initialPublicKey]), "Initial signed feed did not verify");
  console.log("LIVE-C02 PASS — published Ed25519 key verifies the shipping signed feed");

  assert.equal((await fetch(`${baseUrl}/metrics`)).status, 401);
  const metricsBefore = await (await fetch(`${baseUrl}/metrics`, { headers: { Authorization: `Bearer ${metricsToken}` } })).text();
  assert(!metricsBefore.includes(publicCampaign));
  assert(!metricsBefore.includes(governedCampaign));
  assert(!reporterProofs.some((proof) => metricsBefore.includes(proof)));
  assert(!metricsBefore.includes("live-community-controlled@example.test"));
  console.log("LIVE-C03 PASS — metrics require bearer auth and expose no campaign/reporter/message identifiers");

  const forgedTimes = spreadTimes();
  for (let index = 0; index < 5; index++) {
    const receipt = await json(await fetch(`${baseUrl}/api/community/v1/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(report(publicCampaign, index, forgedTimes[index])),
    }), `Community public report ${index + 1}`);
    assert.equal(receipt.accepted, true);
    assert.equal(receipt.duplicate, false);
    assert.equal(receipt.independentReporters, index + 1);
    if (index >= 2) assert.equal(receipt.status, "warning");
    assert.notEqual(receipt.status, "confirmed");
  }
  const preReviewFeed = await json(await fetch(`${baseUrl}/api/community/v1/feed`), "Pre-review feed");
  const preReviewPayload = verifyCommunityFeed(preReviewFeed, [initialPublicKey]);
  assert(preReviewPayload);
  assert(preReviewPayload.entries.every((entry) => entry.confirmedThreat !== true), "Community API auto-confirmed before trusted review");

  await stopService();
  const forgedCandidates = runOps(["review-list", dataDir]);
  assert(Array.isArray(forgedCandidates));
  assert(!forgedCandidates.some((item) => item.campaignFingerprint === publicCampaign), "Client-supplied timestamps forged server temporal corroboration");
  console.log("LIVE-C04 PASS — public reports cannot forge the six-hour/two-day review boundary with client-supplied timestamps");

  seedServerAuthoritativeReviewCandidate(dataDir);
  const candidates = runOps(["review-list", dataDir]);
  assert(Array.isArray(candidates) && candidates.some((item) => candidateMatches(item, governedCampaign)));
  const review = runOps(["review-resolve", dataDir, governedCampaign, "approve", "live-reviewer-001"], {
    EMAIL_SHIELD_COMMUNITY_REVIEW_REASON: "Controlled live acceptance: five independent strong reports were accepted across the required server-authoritative observation window.",
  });
  assert.equal(review.decision, "approved");
  assert.equal(review.reporterHistoriesUpdated, 5);

  baseUrl = await startService(dataDir);
  const postReviewInfo = await json(await fetch(`${baseUrl}/api/community/v1/public-key`), "Post-review public key");
  assert.equal(postReviewInfo.keyId, initialKeyId, "Signing key changed across ordinary restart");
  const postReviewFeed = await json(await fetch(`${baseUrl}/api/community/v1/feed`), "Post-review feed");
  assertConfirmedFeed(postReviewFeed, initialPublicKey);
  const status = await json(await fetch(`${baseUrl}/api/community/v1/status`), "Post-review status");
  assert.equal(status.stats.confirmed, 1);
  console.log("LIVE-C05 PASS — server-authoritative temporal spread plus trusted review promotes to Confirmed and survives restart");

  const metricsAfter = await (await fetch(`${baseUrl}/metrics`, { headers: { Authorization: `Bearer ${metricsToken}` } })).text();
  assert(!metricsAfter.includes(publicCampaign));
  assert(!metricsAfter.includes(governedCampaign));
  assert(!reporterProofs.some((proof) => metricsAfter.includes(proof)));
  await stopService();

  const backup = runOps(["backup", dataDir, backupFile], {
    EMAIL_SHIELD_COMMUNITY_BACKUP_PASSPHRASE_FILE: passphraseFile,
  });
  assert.equal(backup.signingKeyId, initialKeyId);
  assert.equal(backup.aggregateStoragePresent, true);
  assert(statSync(backupFile).size > 0);
  const backupText = readFileSync(backupFile, "utf8");
  assert(!backupText.includes(publicCampaign), "Encrypted backup leaked public probe fingerprint in plaintext");
  assert(!backupText.includes(governedCampaign), "Encrypted backup leaked governed campaign fingerprint in plaintext");
  assert(!backupText.includes("PRIVATE KEY"), "Encrypted backup leaked private signing key in plaintext");
  const restore = runOps(["restore", backupFile, restoredDir], {
    EMAIL_SHIELD_COMMUNITY_BACKUP_PASSPHRASE_FILE: passphraseFile,
  });
  assert.equal(restore.signingKeyId, initialKeyId);
  assert.equal(restore.aggregateStoragePresent, true);

  baseUrl = await startService(restoredDir);
  const restoredInfo = await json(await fetch(`${baseUrl}/api/community/v1/public-key`), "Restored public key");
  assert.equal(restoredInfo.keyId, initialKeyId);
  const restoredFeed = await json(await fetch(`${baseUrl}/api/community/v1/feed`), "Restored feed");
  assertConfirmedFeed(restoredFeed, initialPublicKey);
  await stopService();
  console.log("LIVE-C06 PASS — encrypted backup/restore preserves confirmed state and signing identity without plaintext leakage");

  const rotation = runOps(["prepare-rotation", restoredDir, rotationDir]);
  assert.equal(rotation.currentKeyId, initialKeyId);
  assert.notEqual(rotation.nextKeyId, initialKeyId);
  const privateMode = statSync(rotation.nextPrivateKeyPath).mode & 0o777;
  assert.equal(privateMode, 0o600, `Next signing private key mode was ${privateMode.toString(8)}`);
  const manifest = JSON.parse(readFileSync(rotation.manifestPath, "utf8"));
  assert.equal(manifest.currentKeyId, initialKeyId);
  assert.equal(manifest.nextKeyId, rotation.nextKeyId);
  assert.deepEqual(manifest.sequence, [
    "deploy-overlap-trust",
    "verify-current-feed",
    "activate-next-signing-key",
    "verify-next-feed",
    "retire-current-trust-after-overlap",
  ]);
  const nextPrivateKey = readFileSync(rotation.nextPrivateKeyPath, "utf8");
  const nextPublicKey = readFileSync(rotation.nextPublicKeyPath, "utf8");
  baseUrl = await startService(restoredDir, {
    EMAIL_SHIELD_COMMUNITY_PRIVATE_KEY: nextPrivateKey,
    EMAIL_SHIELD_COMMUNITY_PUBLIC_KEY: nextPublicKey,
  });
  const nextInfo = await json(await fetch(`${baseUrl}/api/community/v1/public-key`), "Rotated public key");
  assert.equal(nextInfo.keyId, rotation.nextKeyId);
  const nextFeed = await json(await fetch(`${baseUrl}/api/community/v1/feed`), "Rotated signed feed");
  const overlapPayload = verifyCommunityFeed(nextFeed, [initialPublicKey, nextPublicKey]);
  assert(overlapPayload, "Rotated feed failed overlap-trust verification");
  assert(overlapPayload.entries.some((entry) => entry.type === "campaign" && entry.value === governedCampaign && entry.confirmedThreat === true));
  console.log("LIVE-C07 PASS — rotation package uses protected private material and next-key feed verifies under explicit overlap trust");

  console.log("COMMUNITY_SHIELD_APP_ACCEPTANCE=PASS");
} finally {
  await stopService();
  rmSync(baseTmp, { recursive: true, force: true });
}
