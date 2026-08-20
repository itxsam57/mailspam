import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import express from "express";
import { afterEach, describe, expect, it } from "vitest";
import type { EmailAdapter } from "../../server/src/canonical/adapter.js";
import { registerProtectionActionRoutes } from "../../server/src/api/protectionActions.js";
import { SessionStore } from "../../server/src/api/sessionStore.js";
import { InMemoryPolicyRepository } from "../../server/src/api/policyPersistence.js";

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

function actionContext() {
  return {
    providerNativeId: "provider-native-1",
    messageId: "message-1",
    exceptionKey: `message:${"b".repeat(64)}`,
    senderAddress: "scammer@fraud.example",
    normalizedFolder: "inbox" as const,
    links: [],
    unsubscribe: { available: false, method: "none" as const, target: null, source: "none" as const, actionKey: null },
    communityReport: {
      campaignFingerprint: "a".repeat(64),
      indicators: [{ type: "campaign" as const, value: "a".repeat(64) }],
      evidenceCodes: ["CALLBACK_SCAM_INTENT"],
      evidenceScore: 3,
      verdict: "review" as const,
    },
  };
}

async function fixture(options: { failMove?: boolean } = {}) {
  const sessions = new SessionStore(new InMemoryPolicyRepository());
  const session = sessions.create("gmail", "Fixture Gmail", { provider: "gmail", mode: "fixture" });
  const trashCalls: string[][] = [];

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

  const app = express();
  app.use(express.json());
  registerProtectionActionRoutes(app, { sessions, adapterFactory });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const { port } = server.address() as AddressInfo;
  return { sessions, session, trashCalls, baseUrl: `http://127.0.0.1:${port}` };
}

async function trash(baseUrl: string, accountId: string, token: string) {
  const response = await fetch(`${baseUrl}/api/accounts/${accountId}/messages/trash`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
  return { response, body: await response.json() as Record<string, unknown> };
}

describe("EMA-39 exact-message Trash response contract", () => {
  it("reports one requested and one moved only after the provider confirms the exact message, then rejects replay", async () => {
    const test = await fixture();
    const registration = test.sessions.registerReviewAction(test.session, actionContext());

    const first = await trash(test.baseUrl, test.session.id, registration.token);
    expect(first.response.status).toBe(200);
    expect(first.body).toMatchObject({
      requested: 1,
      moved: 1,
      failed: [],
      success: true,
      accountId: test.session.id,
      token: registration.token,
    });
    expect(test.trashCalls).toEqual([["provider-native-1"]]);

    const replay = await trash(test.baseUrl, test.session.id, registration.token);
    expect(replay.response.status).toBe(409);
    expect(replay.body.success).not.toBe(true);
    expect(test.trashCalls).toEqual([["provider-native-1"]]);
  });

  it("never returns a successful move contract when the provider fails", async () => {
    const test = await fixture({ failMove: true });
    const registration = test.sessions.registerReviewAction(test.session, actionContext());

    const result = await trash(test.baseUrl, test.session.id, registration.token);
    expect(result.response.status).toBe(502);
    expect(result.body.success).not.toBe(true);
    expect(result.body.moved).not.toBe(1);
    expect(test.trashCalls).toEqual([["provider-native-1"]]);
  });
});