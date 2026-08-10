import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EncryptedCommunityAggregateStore } from "../../server/src/community/aggregateStore.js";
import { createEncryptedCommunityBackup } from "../../server/src/community/operations.js";
import { CommunityNetwork } from "../../server/src/community/network.js";
import {
  COMMUNITY_REPORT_DATABASE_FILE,
  COMMUNITY_REPORT_KEY_FILE,
} from "../../server/src/community/storageFiles.js";
import type { CommunityReportSubmission } from "../../server/src/community/types.js";

const ALGORITHM = "aes-256-gcm";
const AAD = Buffer.from("email-shield-community-reports-v1", "utf8");
const CAMPAIGN = "a".repeat(64);
const REPORTER = "b".repeat(64);
const directories: string[] = [];

interface EncryptedEnvelope {
  version: 1;
  algorithm: "aes-256-gcm";
  iv: string;
  authTag: string;
  ciphertext: string;
}

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-community-state-integrity-"));
  directories.push(directory);
  return directory;
}

function report(reporterProof = REPORTER): CommunityReportSubmission {
  return {
    schemaVersion: 1,
    reporterProof,
    campaignFingerprint: CAMPAIGN,
    reportedAt: new Date().toISOString(),
    verdict: "high_risk",
    evidenceScore: 8,
    evidenceCodes: ["STATE_INTEGRITY_TEST"],
    indicators: [
      { type: "campaign", value: CAMPAIGN },
      { type: "url_domain", value: "state-integrity.example" },
    ],
  };
}

function initializedDirectory(): string {
  const directory = temporaryDirectory();
  const network = new CommunityNetwork({ dataDirectory: directory, serverEnabled: true });
  network.acceptExternalReport(report());
  expect(network.publicInfo().stats.campaigns).toBe(1);
  return directory;
}

function decryptState(directory: string): Record<string, any> {
  const key = readFileSync(join(directory, COMMUNITY_REPORT_KEY_FILE));
  const envelope = JSON.parse(readFileSync(join(directory, COMMUNITY_REPORT_DATABASE_FILE), "utf8")) as EncryptedEnvelope;
  const decipher = createDecipheriv(ALGORITHM, key, Buffer.from(envelope.iv, "base64"));
  decipher.setAAD(AAD);
  decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));
  return JSON.parse(Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8")) as Record<string, any>;
}

function encryptState(directory: string, state: unknown): void {
  const key = readFileSync(join(directory, COMMUNITY_REPORT_KEY_FILE));
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  cipher.setAAD(AAD);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(state), "utf8"), cipher.final()]);
  const envelope: EncryptedEnvelope = {
    version: 1,
    algorithm: ALGORITHM,
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
  writeFileSync(join(directory, COMMUNITY_REPORT_DATABASE_FILE), JSON.stringify(envelope), { mode: 0o600 });
}

function campaign(state: Record<string, any>): Record<string, any> {
  return state.campaigns[CAMPAIGN] as Record<string, any>;
}

function assertUnreadable(directory: string): void {
  const store = new EncryptedCommunityAggregateStore(directory);
  expect(() => store.stats()).toThrow("Encrypted community report database could not be read");
  expect(() => store.buildFeedPayload()).toThrow("Encrypted community report database could not be read");
  expect(() => store.accept(report("c".repeat(64)))).toThrow("Encrypted community report database could not be read");
}

describe("authenticated community aggregate-state integrity", () => {
  it("accepts the exact nested state emitted by the production writer", () => {
    const directory = initializedDirectory();
    const store = new EncryptedCommunityAggregateStore(directory);
    expect(store.stats()).toEqual({ campaigns: 1, warnings: 0, confirmed: 0 });
    expect(store.buildFeedPayload().entries).toEqual([]);
  });

  it.each([
    ["unknown top-level fields", (state: Record<string, any>) => { state.unexpected = true; }],
    ["invalid campaign fingerprints", (state: Record<string, any>) => {
      state.campaigns.not_a_fingerprint = state.campaigns[CAMPAIGN];
      delete state.campaigns[CAMPAIGN];
    }],
    ["unknown campaign fields", (state: Record<string, any>) => { campaign(state).unexpected = true; }],
    ["invalid persisted reporter scores", (state: Record<string, any>) => { campaign(state).reporters[REPORTER].evidenceScore = 21; }],
    ["reporter timestamps outside the campaign interval", (state: Record<string, any>) => {
      const item = campaign(state);
      item.reporters[REPORTER].reportedAt = new Date(Date.parse(item.lastSeen) + 1_000).toISOString();
    }],
    ["duplicate reporter indicators", (state: Record<string, any>) => {
      const reporter = campaign(state).reporters[REPORTER];
      reporter.indicators.push({ ...reporter.indicators[0] });
    }],
    ["missing complete campaign support", (state: Record<string, any>) => {
      campaign(state).reporters[REPORTER].indicators = campaign(state).reporters[REPORTER].indicators
        .filter((item: { type: string }) => item.type !== "campaign");
    }],
    ["duplicate evidence codes", (state: Record<string, any>) => {
      campaign(state).reporters[REPORTER].evidenceCodes.push("STATE_INTEGRITY_TEST");
    }],
  ])("rejects validly encrypted state with %s", (_label, mutate) => {
    const directory = initializedDirectory();
    const state = decryptState(directory);
    mutate(state);
    encryptState(directory, state);
    assertUnreadable(directory);
  });

  it("blocks disaster-recovery backup of validly encrypted but structurally corrupt state", () => {
    const directory = initializedDirectory();
    const state = decryptState(directory);
    campaign(state).reporters[REPORTER].verdict = "invented_verdict";
    encryptState(directory, state);
    const backup = join(temporaryDirectory(), "corrupt-state.eshield");

    expect(() => createEncryptedCommunityBackup({
      dataDirectory: directory,
      backupPath: backup,
      passphrase: "community state integrity backup passphrase",
    })).toThrow("Encrypted community report database could not be read");
    expect(existsSync(backup)).toBe(false);
  });
});
