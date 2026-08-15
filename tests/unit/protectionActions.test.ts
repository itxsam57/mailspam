import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import express from "express";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { EmailAdapter } from "../../server/src/canonical/adapter.js";
import { registerProtectionActionRoutes } from "../../server/src/api/protectionActions.js";
import { SessionStore } from "../../server/src/api/sessionStore.js";
import { InMemoryPolicyRepository } from "../../server/src/api/policyPersistence.js";
import { CommunityNetwork } from "../../server/src/community/network.js";
import type { CommunityReportContext } from "../../server/src/community/types.js";

const servers: Server[] = [];
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function directory(label: string): string {
  const value = mkdtempSync(join(tmpdir(), `email-shield-protection-${label}-`));
  directories.push(value);
  return value;
}

const campaignFingerprint = "a".repeat(64);
const report: CommunityReportContext = {
  campaignFingerprint,
  indicators: [
    { type: "campaign", value: campaignFingerprint },
    { type: "sender", value: "scammer@fraud.example" },
  ],
  evidenceCodes: ["CALLBACK_SCAM_INTENT"],
  evidenceScore: 3,
  verdict: "review",
};

function actionContext(senderAddress = "scammer@fraud.example") {
  return {
    providerNativeId: "provider-native-1",
    messageId: "message-1",
    exceptionKey: `message:${"b".repeat(64)}`,
    senderAddress,
    normalizedFolder: "inbox" as const,
    links: [],
    unsubscribe: { available: false, method: "none" as const, target: null, source: "none" as const, actionKey: null },
    communityReport: structuredClone(report),
  };
}

async function fixture(options: {
  failMove?: boolean;
  familyMode?: "success" | "failure" | "none";
} = {}) {
  const sessions = new SessionStore(new InMemoryPolicyRepository());
  const session = sessions.create("gmail", "Fixture Gmail", { provider: "gmail", mode: "fixture" });
  const community = new CommunityNetwork({
    dataDirectory: directory("community"),
    serverEnabled: false,
    remoteUrl: null,
  });
  const trashCalls: string[][] = [];
  const familyCalls: Array<{ mailboxAccountKey: string; fingerprint: string; source: string }> = [];

  const adapterFactory = (): EmailAdapter => ({
    provider: "gmail",
    connect: async () => {},
    listFolders: async () => [],
    fetchPage: async () => ({ envelopes: [], nextCursor: null, done: true }),
    moveToTrash: async (ids) => {
      trashCalls.push([...ids]);
      if (options.failMove) throw new Error("provider move failed");
    },
    reportSpam: async () => ({ requested: 0, reported: 0, mode: "fixture_junk_move" }),
    disconnect: async () => {},
  });

  const familyThreats = options.familyMode === "none"
    ? undefined
    : {
        recordFamilyThreat: vi.fn((mailboxAccountKey: string, fingerprint: string, source: "report_scam" | "family_block") => {
          familyCalls.push({ mailboxAccountKey, fingerprint, source });
          if (options.familyMode === "failure") throw new Error("family sync unavailable");
          return {
            familyCircleId: "family_test",
            accountId: "acct_test",
            entries: [{ campaignFingerprint: fingerprint, status: source === "report_scam" ? "warning" as const : "warning" as const }],
          };
        }),
      };

  const app = express();
  app.use(express.json());
  registerProtectionActionRoutes(app, { sessions, community, adapterFactory, familyThreats });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const { port } = server.address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;
  return { sessions, session, community, trashCalls, familyCalls, familyThreats, baseUrl };
}

async function post(baseUrl: string, accountId: string, path: string, body: object) {
  const response = await fetch(`${baseUrl}/api/accounts/${accountId}/messages/${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return { response, body: await response.json() as Record<string, unknown> };
}

describe("durable block action API", () => {
  it("derives sender identity from the opaque scan token, persists the block, and trashes exactly the selected message", async () => {
    const test = await fixture();
    const registration = test.sessions.registerReviewAction(test.session, actionContext());

    const result = await post(test.baseUrl, test.session.id, "block-sender", {
      token: registration.token,
      address: "victim@example.test",
      domain: "example.test",
    });

    expect(result.response.status).toBe(200);
    expect(result.body).toMatchObject({ blocked: true, scope: "sender", value: "scammer@fraud.example", movedCurrent: true });
    expect(test.session.personalPolicy.isBlockedSender("scammer@fraud.example")).toBe(true);
    expect(test.session.personalPolicy.isBlockedSender("victim@example.test")).toBe(false);
    expect(test.trashCalls).toEqual([["provider-native-1"]]);
  });

  it("keeps a pre-stop message block action valid through Stop/Resume housekeeping", async () => {
    const test = await fixture();
    const registration = test.sessions.registerReviewAction(test.session, actionContext());

    // scanStream invokes this boundary when starting/resuming. Retained rows in
    // the current workspace must keep their bounded opaque actions usable.
    test.sessions.clearScanActions(test.session);

    const result = await post(test.baseUrl, test.session.id, "block-sender", { token: registration.token });
    expect(result.response.status).toBe(200);
    expect(result.body).toMatchObject({
      blocked: true,
      scope: "sender",
      value: "scammer@fraud.example",
      movedCurrent: true,
    });
    expect(test.session.personalPolicy.isBlockedSender("scammer@fraud.example")).toBe(true);
    expect(test.trashCalls).toEqual([["provider-native-1"]]);
  });

  it("rejects the exact stale second-tab Block replay with 409 and no second provider mutation", async () => {
    const test = await fixture();
    const registration = test.sessions.registerReviewAction(test.session, actionContext());
    const first = await post(test.baseUrl, test.session.id, "block-sender", { token: registration.token });
    const stale = await post(test.baseUrl, test.session.id, "block-sender", { token: registration.token });

    expect(first.response.status).toBe(200);
    expect(stale.response.status).toBe(409);
    expect(String(stale.body.error)).toContain("already used");
    expect(test.trashCalls).toEqual([["provider-native-1"]]);
  });

  it("refuses broad shared consumer-domain blocks before policy or provider mutation", async () => {
    const test = await fixture();
    const registration = test.sessions.registerReviewAction(test.session, actionContext("person@gmail.com"));
    const result = await post(test.baseUrl, test.session.id, "block-domain", { token: registration.token });

    expect(result.response.status).toBe(409);
    expect(String(result.body.error)).toContain("shared mailbox domain gmail.com");
    expect(test.session.personalPolicy.isBlockedDomain("gmail.com")).toBe(false);
    expect(test.trashCalls).toEqual([]);
  });

  it("persists a normal domain block and moves the current selected message", async () => {
    const test = await fixture();
    const registration = test.sessions.registerReviewAction(test.session, actionContext("offers@fraud.example"));
    const result = await post(test.baseUrl, test.session.id, "block-domain", { token: registration.token });

    expect(result.response.status).toBe(200);
    expect(result.body).toMatchObject({ blocked: true, scope: "domain", value: "fraud.example", movedCurrent: true });
    expect(test.session.personalPolicy.isBlockedDomain("fraud.example")).toBe(true);
    expect(test.trashCalls).toEqual([["provider-native-1"]]);
  });

  it("keeps the durable block active if the current provider Trash move fails and permits a disposal retry", async () => {
    const test = await fixture({ failMove: true });
    const registration = test.sessions.registerReviewAction(test.session, actionContext());
    const first = await post(test.baseUrl, test.session.id, "block-sender", { token: registration.token });
    const retry = await post(test.baseUrl, test.session.id, "block-sender", { token: registration.token });

    expect(first.response.status).toBe(207);
    expect(first.body).toMatchObject({ blocked: true, movedCurrent: false });
    expect(test.session.personalPolicy.isBlockedSender("scammer@fraud.example")).toBe(true);
    expect(retry.response.status).toBe(207);
    expect(test.trashCalls).toHaveLength(2);
  });

  it("keeps Block personal by default and shares only campaign fingerprint when Family Shield is explicitly chosen", async () => {
    const personal = await fixture({ familyMode: "success" });
    let registration = personal.sessions.registerReviewAction(personal.session, actionContext());
    const personalResult = await post(personal.baseUrl, personal.session.id, "block-sender", { token: registration.token });
    expect(personalResult.response.status).toBe(200);
    expect(personal.familyCalls).toEqual([]);

    const shared = await fixture({ familyMode: "success" });
    registration = shared.sessions.registerReviewAction(shared.session, actionContext());
    const sharedResult = await post(shared.baseUrl, shared.session.id, "block-sender", { token: registration.token, shareWithFamily: true });
    expect(sharedResult.response.status).toBe(200);
    expect(sharedResult.body).toMatchObject({ family: { shared: true, status: "warning" } });
    expect(shared.familyCalls).toEqual([{
      mailboxAccountKey: shared.session.policyAccountKey,
      fingerprint: campaignFingerprint,
      source: "family_block",
    }]);
    expect(JSON.stringify(shared.familyCalls)).not.toMatch(/scammer@|subject|provider-native|message-1/i);
  });

  it("never rolls back a personal Block when Family Shield synchronization fails", async () => {
    const test = await fixture({ familyMode: "failure" });
    const registration = test.sessions.registerReviewAction(test.session, actionContext());
    const result = await post(test.baseUrl, test.session.id, "block-sender", { token: registration.token, shareWithFamily: true });

    expect(result.response.status).toBe(200);
    expect(result.body).toMatchObject({ blocked: true, movedCurrent: true, family: { shared: false, error: "family sync unavailable" } });
    expect(test.session.personalPolicy.isBlockedSender("scammer@fraud.example")).toBe(true);
    expect(test.trashCalls).toEqual([["provider-native-1"]]);
  });

  it("records positive campaign feedback without exposing a sender/domain allowlist", async () => {
    const test = await fixture();
    const registration = test.sessions.registerReviewAction(test.session, actionContext());
    const result = await post(test.baseUrl, test.session.id, "legitimate-feedback", { token: registration.token });

    expect(result.response.status).toBe(200);
    expect(result.body).toMatchObject({ accepted: true, independentReporters: 1 });
    expect(test.community.getVerifiedEntries()).toEqual([]);

    const staleThreat = await post(test.baseUrl, test.session.id, "legitimate-feedback", { token: registration.token });
    expect(staleThreat.response.status).toBe(409);
  });

  it("makes Report Scam authoritative for local campaign Trash while preserving privacy-reduced Family/community thresholds", async () => {
    const test = await fixture({ familyMode: "success" });
    const registration = test.sessions.registerReviewAction(test.session, actionContext());
    const result = await post(test.baseUrl, test.session.id, "report-scam", { token: registration.token, blockSender: true });

    expect(result.response.status).toBe(200);
    expect(result.body).toMatchObject({
      success: true,
      localProtected: true,
      senderBlocked: true,
      movedCurrent: true,
      providerAction: "trash",
      communityAccepted: true,
      accepted: true,
      independentReporters: 1,
      family: { shared: true, status: "warning" },
    });
    expect(test.session.personalPolicy.isReportedCampaign(campaignFingerprint)).toBe(true);
    expect(test.session.personalPolicy.isBlockedSender("scammer@fraud.example")).toBe(true);
    expect(test.trashCalls).toEqual([["provider-native-1"]]);
    expect(test.familyCalls).toEqual([{
      mailboxAccountKey: test.session.policyAccountKey,
      fingerprint: campaignFingerprint,
      source: "report_scam",
    }]);

    const stale = await post(test.baseUrl, test.session.id, "report-scam", { token: registration.token });
    expect(stale.response.status).toBe(409);
  });

  it("keeps Report Scam local protection and current Trash authoritative when Family Shield synchronization fails", async () => {
    const test = await fixture({ familyMode: "failure" });
    const registration = test.sessions.registerReviewAction(test.session, actionContext());
    const result = await post(test.baseUrl, test.session.id, "report-scam", { token: registration.token });

    expect(result.response.status).toBe(207);
    expect(result.body).toMatchObject({
      success: true,
      localProtected: true,
      movedCurrent: true,
      providerAction: "trash",
      communityAccepted: true,
      accepted: true,
      family: { shared: false, error: "family sync unavailable" },
    });
    expect(test.session.personalPolicy.isReportedCampaign(campaignFingerprint)).toBe(true);
    expect(test.trashCalls).toEqual([["provider-native-1"]]);

    const stale = await post(test.baseUrl, test.session.id, "report-scam", { token: registration.token });
    expect(stale.response.status).toBe(409);
  });

  it("never rolls back the reported-campaign rule when the current provider Trash move fails", async () => {
    const test = await fixture({ failMove: true, familyMode: "success" });
    const registration = test.sessions.registerReviewAction(test.session, actionContext());
    const result = await post(test.baseUrl, test.session.id, "report-scam", { token: registration.token });

    expect(result.response.status).toBe(207);
    expect(result.body).toMatchObject({
      success: true,
      localProtected: true,
      movedCurrent: false,
      providerAction: "trash_pending",
      moveError: "provider move failed",
      communityAccepted: true,
    });
    expect(test.session.personalPolicy.isReportedCampaign(campaignFingerprint)).toBe(true);
    expect(test.trashCalls).toEqual([["provider-native-1"]]);
  });
});
