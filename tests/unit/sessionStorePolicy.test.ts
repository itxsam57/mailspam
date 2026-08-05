import { describe, expect, it } from "vitest";
import { SessionStore } from "../../server/src/api/sessionStore.js";
import {
  InMemoryPolicyRepository,
  type PersonalPolicyRepository,
} from "../../server/src/api/policyPersistence.js";
import type { ScanActionContext } from "../../server/src/workflows/scanWorkflows.js";

function reviewContext(overrides: Partial<ScanActionContext> = {}): ScanActionContext {
  return {
    providerNativeId: "uid-1",
    messageId: "message-1",
    exceptionKey: `message:${"a".repeat(64)}`,
    senderAddress: "sender@example.com",
    unsubscribe: { available: false, method: "none", target: null, source: "none" },
    ...overrides,
  };
}

describe("account-scoped personal policy", () => {
  it("does not leak rules between different accounts", () => {
    const repository = new InMemoryPolicyRepository();
    const store = new SessionStore(repository);
    const first = store.create("icloud", "first", {
      provider: "icloud", mode: "live", credentials: { user: "first@icloud.com", appPassword: "test" },
    });
    const second = store.create("icloud", "second", {
      provider: "icloud", mode: "live", credentials: { user: "second@icloud.com", appPassword: "test" },
    });

    first.personalPolicy.blockSender("blocked@example.com");
    first.personalPolicy.blockDomain("example.net");
    first.personalPolicy.trustSender("trusted@example.org");
    first.personalPolicy.approveException(`message:${"b".repeat(64)}`);
    first.personalPolicy.rememberUnsubscribed("campaign-key");
    store.persistPersonalPolicy(first);

    expect(second.personalPolicy.isBlockedSender("blocked@example.com")).toBe(false);
    expect(second.personalPolicy.isBlockedDomain("example.net")).toBe(false);
    expect(second.personalPolicy.isTrustedSender("trusted@example.org")).toBe(false);
    expect(second.personalPolicy.isApprovedException(`message:${"b".repeat(64)}`)).toBe(false);
    expect(second.personalPolicy.isUnsubscribedAction("campaign-key")).toBe(false);
  });

  it("shares one live policy object between simultaneous sessions for the same mailbox", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const first = store.create("icloud", "first tab", {
      provider: "icloud", mode: "live", credentials: { user: "same@icloud.com", appPassword: "first" },
    });
    const second = store.create("icloud", "second tab", {
      provider: "icloud", mode: "live", credentials: { user: "SAME@ICLOUD.COM", appPassword: "second" },
    });
    first.personalPolicy.trustSender("trusted@example.com");
    expect(second.personalPolicy).toBe(first.personalPolicy);
    expect(second.personalPolicy.isTrustedSender("trusted@example.com")).toBe(true);
  });

  it("restores blocks, trust, exact approvals, and unsubscribe history after restart", async () => {
    const repository = new InMemoryPolicyRepository();
    const config = {
      provider: "icloud" as const,
      mode: "live" as const,
      credentials: { user: "Usama@iCloud.com", appPassword: "first-password" },
    };
    const firstProcess = new SessionStore(repository);
    const original = firstProcess.create("icloud", "original", config);
    original.personalPolicy.blockSender("blocked@example.com");
    original.personalPolicy.trustSender("trusted@example.com");
    original.personalPolicy.approveException(`message:${"c".repeat(64)}`);
    original.personalPolicy.rememberUnsubscribed("campaign-key");
    firstProcess.persistPersonalPolicy(original);
    await firstProcess.remove(original.id);

    const restartedProcess = new SessionStore(repository);
    const reconnected = restartedProcess.create("icloud", "reconnected", {
      ...config,
      credentials: { user: "usama@icloud.com", appPassword: "new-password" },
    });
    expect(reconnected.personalPolicy.isBlockedSender("blocked@example.com")).toBe(true);
    expect(reconnected.personalPolicy.isTrustedSender("trusted@example.com")).toBe(true);
    expect(reconnected.personalPolicy.isApprovedException(`message:${"c".repeat(64)}`)).toBe(true);
    expect(reconnected.personalPolicy.isUnsubscribedAction("campaign-key")).toBe(true);
  });

  it("rolls back a mutation when encrypted persistence fails", () => {
    const failingRepository: PersonalPolicyRepository = {
      load: () => ({
        blockedSenders: ["original@example.com"],
        blockedDomains: [],
        trustedSenders: [],
        approvedExceptions: [],
        unsubscribedActions: [],
      }),
      save: () => { throw new Error("disk full"); },
    };
    const store = new SessionStore(failingRepository);
    const session = store.create("icloud", "fixture", { provider: "icloud", mode: "fixture" });

    expect(() => store.mutateAndPersistPersonalPolicy(
      session,
      (policy) => policy.trustSender("should-not-remain@example.com"),
    )).toThrow("disk full");
    expect(session.personalPolicy.isBlockedSender("original@example.com")).toBe(true);
    expect(session.personalPolicy.isTrustedSender("should-not-remain@example.com")).toBe(false);
  });
});

describe("opaque message review actions", () => {
  it("issues account-scoped tokens without exposing the policy key in the token", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const first = store.create("gmail", "first", { provider: "gmail", mode: "fixture" });
    const second = store.create("outlook", "second", { provider: "outlook", mode: "fixture" });
    const context = reviewContext();
    const registered = store.registerReviewAction(first, context);

    expect(registered.token).not.toContain(context.exceptionKey);
    expect(store.resolveReviewAction(first, registered.token)).toMatchObject({
      exceptionKey: context.exceptionKey,
      senderAddress: context.senderAddress,
      providerNativeId: context.providerNativeId,
    });
    expect(() => store.resolveReviewAction(second, registered.token)).toThrow("unknown or expired");
  });

  it("reports existing exact-message and trusted-sender decisions", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const session = store.create("yahoo", "mailbox", { provider: "yahoo", mode: "fixture" });
    const context = reviewContext();
    session.personalPolicy.approveException(context.exceptionKey);
    session.personalPolicy.trustSender(context.senderAddress!);

    expect(store.registerReviewAction(session, context)).toMatchObject({
      alreadyApproved: true,
      senderTrusted: true,
    });
  });
});

describe("account-scoped unsubscribe actions", () => {
  it("issues opaque unique tokens while grouping duplicate campaign targets", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const session = store.create("icloud", "mailbox", {
      provider: "icloud", mode: "live", credentials: { user: "same@icloud.com", appPassword: "test" },
    });

    const first = store.registerUnsubscribeAction(session, "one_click_post", "https://example.test/unsub?id=1", "uid-1");
    const second = store.registerUnsubscribeAction(session, "one_click_post", "https://example.test/unsub?id=1", "uid-2");

    expect(first.token).not.toBe(second.token);
    expect(first.actionKey).toBe(second.actionKey);
    expect(first.token).not.toContain("example.test");
    expect(store.resolveUnsubscribeAction(session, first.token)).toMatchObject({
      method: "one_click_post",
      target: "https://example.test/unsub?id=1",
      providerNativeId: "uid-1",
      actionKey: first.actionKey,
    });
  });

  it("does not merge manual links and one-click posts that share a URL", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const session = store.create("imap", "mailbox", { provider: "imap", mode: "fixture" });
    const automatic = store.registerUnsubscribeAction(session, "one_click_post", "https://example.test/unsub", "uid-1");
    const manual = store.registerUnsubscribeAction(session, "link_only", "https://example.test/unsub", "uid-2");
    expect(automatic.actionKey).not.toBe(manual.actionKey);
  });

  it("persists completed unsubscribe status and survives token clearing", () => {
    const repository = new InMemoryPolicyRepository();
    const store = new SessionStore(repository);
    const session = store.create("yahoo", "mailbox", { provider: "yahoo", mode: "fixture" });
    const action = store.registerUnsubscribeAction(session, "one_click_post", "https://example.test/unsub", "uid-1");
    store.markUnsubscribed(session, action.actionKey);
    store.clearScanActions(session);

    expect(() => store.resolveUnsubscribeAction(session, action.token)).toThrow("unknown or expired");
    expect(session.personalPolicy.isUnsubscribedAction(action.actionKey)).toBe(true);
    expect(store.registerUnsubscribeAction(session, "one_click_post", "https://example.test/unsub", "uid-2").alreadyUnsubscribed).toBe(true);
  });
});
