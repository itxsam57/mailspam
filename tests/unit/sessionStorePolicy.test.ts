import { describe, expect, it } from "vitest";
import { SessionStore } from "../../server/src/api/sessionStore.js";

describe("account-scoped personal policy", () => {
  it("does not leak blocked senders or domains between connected accounts", () => {
    const store = new SessionStore();
    const first = store.create("icloud", "first", { provider: "icloud", mode: "fixture" });
    const second = store.create("yahoo", "second", { provider: "yahoo", mode: "fixture" });

    first.personalPolicy.blockSender("60481385@msbinstitute.com");
    first.personalPolicy.blockDomain("msbinstitute.com");

    expect(first.personalPolicy.isBlockedSender("60481385@msbinstitute.com")).toBe(true);
    expect(first.personalPolicy.isBlockedDomain("msbinstitute.com")).toBe(true);
    expect(second.personalPolicy.isBlockedSender("60481385@msbinstitute.com")).toBe(false);
    expect(second.personalPolicy.isBlockedDomain("msbinstitute.com")).toBe(false);
  });

  it("creates a fresh policy store when an account is reconnected", async () => {
    const store = new SessionStore();
    const original = store.create("icloud", "original", { provider: "icloud", mode: "fixture" });
    original.personalPolicy.blockSender("blocked@example.com");

    await store.remove(original.id);
    const reconnected = store.create("icloud", "reconnected", { provider: "icloud", mode: "fixture" });

    expect(reconnected.personalPolicy.isBlockedSender("blocked@example.com")).toBe(false);
  });
});
