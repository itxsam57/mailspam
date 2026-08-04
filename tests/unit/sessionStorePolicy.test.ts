import { describe, expect, it } from "vitest";
import { SessionStore } from "../../server/src/api/sessionStore.js";
import { InMemoryPolicyRepository } from "../../server/src/api/policyPersistence.js";

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

  it("restores persisted rules when the same mailbox reconnects", async () => {
    const repository = new InMemoryPolicyRepository();
    const store = new SessionStore(repository);
    const config = {
      provider: "icloud" as const,
      mode: "live" as const,
      credentials: { user: "Usama@iCloud.com", appPassword: "first-password" },
    };
    const original = store.create("icloud", "original", config);
    original.personalPolicy.blockSender("blocked@example.com");
    original.personalPolicy.blockDomain("example.net");
    store.persistPersonalPolicy(original);

    await store.remove(original.id);
    const reconnected = store.create("icloud", "reconnected", {
      ...config,
      credentials: { user: "usama@icloud.com", appPassword: "new-password" },
    });

    expect(reconnected.personalPolicy.isBlockedSender("blocked@example.com")).toBe(true);
    expect(reconnected.personalPolicy.isBlockedDomain("example.net")).toBe(true);
  });

  it("rolls back cleanly when a caller replaces a failed mutation snapshot", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const session = store.create("icloud", "fixture", { provider: "icloud", mode: "fixture" });
    session.personalPolicy.blockSender("original@example.com");
    const previous = session.personalPolicy.snapshot();

    session.personalPolicy.blockSender("should-not-remain@example.com");
    session.personalPolicy.replace(previous);

    expect(session.personalPolicy.isBlockedSender("original@example.com")).toBe(true);
    expect(session.personalPolicy.isBlockedSender("should-not-remain@example.com")).toBe(false);
  });
});
