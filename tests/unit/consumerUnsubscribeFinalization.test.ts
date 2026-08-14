import express from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { SessionStore } from "../../server/src/api/sessionStore.js";
import { InMemoryPolicyRepository } from "../../server/src/api/policyPersistence.js";
import { registerConsumerUnsubscribeActivityRoutes } from "../../server/src/api/consumerUnsubscribeActivityRoutes.js";
import {
  normalizeManualUnsubscribeTarget,
  unsubscribeCapability,
} from "../../server/src/workflows/unsubscribe.js";

const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  return {
    provider: "gmail",
    accountProof: "proof",
    messageId: "message-id",
    providerNativeId: "native-id",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Newsletter", address: "news@example.com", domain: "example.com" },
    replyTo: null,
    subject: "Newsletter",
    date: new Date(0).toISOString(),
    authentication: { providerTrust: "trusted", spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview: "Newsletter content",
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: false, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 1000, encoding: "html", contentCoverage: "complete" },
    ...overrides,
  };
}

async function startManualActivityFixture() {
  const sessions = new SessionStore(new InMemoryPolicyRepository());
  const session = sessions.create("gmail", "Fixture Gmail", { provider: "gmail", mode: "fixture" });
  const appendActivity = vi.fn((accountKey: string, input: any) => ({
    ...input,
    activityId: "act_123e4567-e89b-42d3-a456-426614174000",
    createdAt: Date.now(),
  }));
  const app = express();
  app.use(express.json());
  registerConsumerUnsubscribeActivityRoutes(app, { sessions, activity: { appendActivity } });
  const server = app.listen(0, "127.0.0.1");
  servers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { sessions, session, appendActivity, baseUrl };
}

describe("consumer unsubscribe discovery", () => {
  it("recognizes a manual newsletter unsubscribe from a clear URL even when the anchor copy is generic", () => {
    const capability = unsubscribeCapability(envelope({
      links: [{
        visibleText: "Click here",
        rawUrl: "https://news.example.com/account/email-preferences?campaign=42",
        normalizedUrl: "https://news.example.com/account/email-preferences?campaign=42",
        claimedBrand: null,
        brandDomainMismatch: null,
      }],
    }));
    expect(capability).toMatchObject({
      available: true,
      method: "link_only",
      source: "message_footer",
    });
  });

  it("recognizes body mailto opt-out requests without turning unrelated links into unsubscribe actions", () => {
    const mail = unsubscribeCapability(envelope({
      links: [{
        visibleText: "Click here",
        rawUrl: "mailto:remove@example.com?subject=unsubscribe",
        normalizedUrl: "mailto:remove@example.com?subject=unsubscribe",
        claimedBrand: null,
        brandDomainMismatch: null,
      }],
    }));
    expect(mail).toMatchObject({ available: true, method: "mailto", source: "message_footer" });

    const unrelated = unsubscribeCapability(envelope({
      links: [{
        visibleText: "Read more",
        rawUrl: "https://example.com/articles/42",
        normalizedUrl: "https://example.com/articles/42",
        claimedBrand: null,
        brandDomainMismatch: null,
      }],
    }));
    expect(unrelated).toEqual({ available: false, method: "none", target: null, source: "none" });
  });

  it("keeps attacker-controlled manual destinations behind the existing URL safety boundary", () => {
    expect(() => normalizeManualUnsubscribeTarget("link_only", "javascript:alert(1)")).toThrow();
    expect(() => normalizeManualUnsubscribeTarget("link_only", "http://localhost/unsubscribe")).toThrow();
    expect(() => normalizeManualUnsubscribeTarget("link_only", "http://127.0.0.1/unsubscribe")).toThrow();
    expect(() => normalizeManualUnsubscribeTarget("link_only", "https://user:pass@example.com/unsubscribe")).toThrow();
  });
});

describe("manual unsubscribe Activity truthfulness", () => {
  it("records a manual page handoff without falsely marking the campaign as completed", async () => {
    const test = await startManualActivityFixture();
    const action = test.sessions.registerUnsubscribeAction(
      test.session,
      "link_only",
      "https://example.com/unsubscribe?id=1",
      "provider-native-1",
    );

    const response = await fetch(`${test.baseUrl}/api/consumer/v1/accounts/${test.session.id}/unsubscribe-activity`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: action.token }),
    });
    expect(response.status).toBe(201);
    expect(await response.json()).toMatchObject({
      recorded: true,
      method: "link_only",
      actionKey: action.actionKey,
      completionVerified: false,
    });
    expect(test.appendActivity).toHaveBeenCalledWith(test.session.policyAccountKey, expect.objectContaining({
      kind: "unsubscribed",
      title: "Unsubscribe page opened",
      reasonCodes: ["MANUAL_UNSUBSCRIBE_PAGE_OPENED"],
    }));
    expect(test.session.personalPolicy.isUnsubscribedAction(action.actionKey)).toBe(false);
  });

  it("rejects attempts to use the manual-history route for an automatic one-click action", async () => {
    const test = await startManualActivityFixture();
    const action = test.sessions.registerUnsubscribeAction(
      test.session,
      "one_click_post",
      "https://example.com/unsubscribe?id=1",
      "provider-native-1",
    );
    const response = await fetch(`${test.baseUrl}/api/consumer/v1/accounts/${test.session.id}/unsubscribe-activity`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: action.token }),
    });
    expect(response.status).toBe(409);
    expect(test.appendActivity).not.toHaveBeenCalled();
  });
});