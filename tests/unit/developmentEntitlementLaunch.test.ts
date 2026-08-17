import { describe, expect, it } from "vitest";
import { enforceDevelopmentEntitlementBoundary } from "../../scripts/development-entitlement-boundary.mjs";

const FLAG = "EMAIL_SHIELD_ENABLE_DEVELOPMENT_ENTITLEMENTS";

describe("development entitlement launch boundary", () => {
  it("removes a stale entitlement flag from the normal source launcher after local env loading", () => {
    const env: Record<string, string | undefined> = { [FLAG]: "1" };
    enforceDevelopmentEntitlementBoundary(env, false);
    expect(env[FLAG]).toBeUndefined();
  });

  it("makes the dedicated fixture launcher authoritative even when local env tries to disable it", () => {
    const env: Record<string, string | undefined> = { [FLAG]: "0" };
    enforceDevelopmentEntitlementBoundary(env, true);
    expect(env[FLAG]).toBe("1");
  });

  it("does not invent the entitlement flag for ordinary source startup", () => {
    const env: Record<string, string | undefined> = {};
    enforceDevelopmentEntitlementBoundary(env, false);
    expect(Object.hasOwn(env, FLAG)).toBe(false);
  });
});
