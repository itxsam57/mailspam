import { describe, expect, it } from "vitest";
import { SessionStore } from "../../server/src/api/sessionStore.js";
import {
  InMemoryPolicyRepository,
  type PersonalPolicyRepository,
} from "../../server/src/api/policyPersistence.js";

describe("account-scoped personal policy", () => {
  it("does not leak blocked senders or domains between different accounts", () => {
    const repository = new InMemoryPolicyRepository();
    const store = new SessionStore(repository);
    const first = store.create("icloud", "first", {
      provider: "icloud",
      mode: "live",
      credentials: { user: "first@icloud.com", appPassword: "test" },
    });
    const second = store.create("icloud", "second", {
      provider: "icloud",
      mode: "live",
      credentials: { user: "second@icloud.com", appPassword: "test" },
    });

    first.personalPolicy.blockSender("60481385@msbinstitute.com");
    first.personalPolicy.blockDomain("msbinstitute.com");
    store.persistPersonalPolicy(first);

    expect(first.personalPolicy.isBlockedSender("60481385@msbinstitute.com")).toBe(true);
    expect(first.personalPolicy.isBlockedDomain("msbinstitute.com")).toBe(true);
    expect(second.personalPolicy.isBlockedSender("60481385@msbinstitute.com")).toBe(false);
    expect(second.personalPolicy.isBlockedDomain("msbinstitute.com")).toBe(false);
  });

  it("shares one live policy object between simultaneous sessions for the same mailbox", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const first = store.create("icloud", "first tab", {
      provider: "icloud",
      mode: "live",
      credentials: { user: "same@icloud.com", appPassword: "first" },
    });
    const second = store.create("icloud", "second tab", {
      provider: "icloud",
      mode: "live",
      credentials: { user: "SAME@ICLOUD.COM", appPassword: "second" },
    });

    first.personalPolicy.blockSender("blocked@example.com");

    expect(second.personalPolicy).toBe(first.personalPolicy);
    expect(second.personalPolicy.isBlockedSender("blocked@example.com")).toBe(true);
  });

  it("restores persisted rules when the same mailbox reconnects", async () => {
    const repository = new InMemoryPolicyRepository();
    const firstProcess = new SessionStore(repository);
    const config = {
      provider: "icloud" as const,
      mode: "live" as const,
      credentials: { user: "Usama@iCloud.com", appPassword: "first-password" },
    };
    const original = firstProcess.create("icloud", "original", config);
    original.personalPolicy.blockSender("blocked@example.com");
    original.personalPolicy.blockDomain("example.net");
    firstProcess.persistPersonalPolicy(original);
    await firstProcess.remove(original.id);

    const restartedProcess = new SessionStore(repository);
    const reconnected = restartedProcess.create("icloud", "reconnected", {
      ...config,
      credentials: { user: "usama@icloud.com", appPassword: "new-password" },
    });

    expect(reconnected.personalPolicy.isBlockedSender("blocked@example.com")).toBe(true);
    expect(reconnected.personalPolicy.isBlockedDomain("example.net")).toBe(true);
  });

  it("rolls back the mutation when encrypted persistence fails", () => {
    const failingRepository: PersonalPolicyRepository = {
      load: () => ({
        blockedSenders: ["original@example.com"],
        blockedDomains: [],
        trustedSenders: [],
        approvedExceptions: [],
      }),
      save: () => { throw new Error("disk full"); },
    };
    const store = new SessionStore(failingRepository);
    const session = store.create("icloud", "fixture", { provider: "icloud", mode: "fixture" });

    expect(() => store.mutateAndPersistPersonalPolicy(
      session,
      (policy) => policy.blockSender("should-not-remain@example.com"),
    )).toThrow("disk full");

    expect(session.personalPolicy.isBlockedSender("original@example.com")).toBe(true);
    expect(session.personalPolicy.isBlockedSender("should-not-remain@example.com")).toBe(false);
  });
});

describe("account-scoped unsubscribe actions", () => {
  it("issues opaque unique tokens while grouping duplicate campaign targets", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const session = store.create("icloud", "mailbox", {
      provider: "icloud",
      mode: "live",
      credentials: { user: "same@icloud.com", appPassword: "test" },
    });

    const first = store.registerUnsubscribeAction(session, "https://example.test/unsub?id=1", "uid-1");
    const second = store.registerUnsubscribeAction(session, "https://example.test/unsub?id=1", "uid-2");

    expect(first.token).not.toBe(second.token);
    expect(first.actionKey).toBe(second.actionKey);
    expect(store.resolveUnsubscribeAction(session, first.token)).toMatchObject({
      target: "https://example.test/unsub?id=1",
      providerNativeId: "uid-1",
      actionKey: first.actionKey,
    });
  });

  it("does not accept another account's unsubscribe token", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const first = store.create("icloud", "first", {
      provider: "icloud",
      mode: "live",
      credentials: { user: "first@icloud.com", appPassword: "test" },
    });
    const second = store.create("icloud", "second", {
      provider: "icloud",
      mode: "live",
      credentials: { user: "second@icloud.com", appPassword: "test" },
    });
    const action = store.registerUnsubscribeAction(first, "https://example.test/unsub", "uid-1");

    expect(() => store.resolveUnsubscribeAction(second, action.token)).toThrow("unknown or expired");
    expect(() => store.resolveUnsubscribeAction(first, "not-a-token")).toThrow("valid unsubscribe action token");
  });

  it("shares duplicate unsubscribe history only between sessions for the same mailbox", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const first = store.create("icloud", "first tab", {
      provider: "icloud",
      mode: "live",
      credentials: { user: "same@icloud.com", appPassword: "first" },
    });
    const second = store.create("icloud", "second tab", {
      provider: "icloud",
      mode: "live",
      credentials: { user: "SAME@ICLOUD.COM", appPassword: "second" },
    });
    const other = store.create("icloud", "other mailbox", {
      provider: "icloud",
      mode: "live",
      credentials: { user: "other@icloud.com", appPassword: "test" },
    });
    const action = store.registerUnsubscribeAction(first, "https://example.test/unsub", "uid-1");
    store.markUnsubscribed(first, action.actionKey);

    expect(second.unsubscribedActionKeys.has(action.actionKey)).toBe(true);
    expect(other.unsubscribedActionKeys.has(action.actionKey)).toBe(false);
  });

  it("clears old action tokens before a new scan without clearing duplicate history", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const session = store.create("icloud", "mailbox", { provider: "icloud", mode: "fixture" });
    const action = store.registerUnsubscribeAction(session, "https://example.test/unsub", "uid-1");
    store.markUnsubscribed(session, action.actionKey);

    store.clearUnsubscribeActions(session);

    expect(() => store.resolveUnsubscribeAction(session, action.token)).toThrow("unknown or expired");
    expect(session.unsubscribedActionKeys.has(action.actionKey)).toBe(true);
  });
});
