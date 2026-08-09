import { afterEach, describe, expect, it, vi } from "vitest";
import { exchangeMicrosoftAuthorizationCode } from "../../server/src/oauth/microsoftOAuth.js";

function successPayload(scope?: string) {
  return new Response(JSON.stringify({
    access_token: "access-private",
    refresh_token: "refresh-private",
    ...(scope === undefined ? {} : { scope }),
  }), { status: 200, headers: { "Content-Type": "application/json" } });
}

afterEach(() => vi.unstubAllGlobals());

describe("Microsoft token response compatibility", () => {
  it("accepts a valid refresh token when Microsoft omits offline_access from the access-token scope list", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => successPayload("User.Read Mail.ReadWrite")));
    const result = await exchangeMicrosoftAuthorizationCode({
      clientId: "public-client-id",
      code: "authorization-code-private",
      codeVerifier: "a".repeat(64),
      redirectUri: "http://localhost:43123",
    });
    expect(result.refreshToken).toBe("refresh-private");
    expect(result.grantedScopes).toEqual(["User.Read", "Mail.ReadWrite"]);
  });

  it("accepts Microsoft's optional missing scope field only when the required token fields are present", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => successPayload(undefined)));
    const result = await exchangeMicrosoftAuthorizationCode({
      clientId: "public-client-id",
      code: "authorization-code-private",
      codeVerifier: "a".repeat(64),
      redirectUri: "http://localhost:43123",
    });
    expect(result.refreshToken).toBe("refresh-private");
  });

  it("still rejects a response that lacks the required mailbox access scope", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => successPayload("User.Read")));
    await expect(exchangeMicrosoftAuthorizationCode({
      clientId: "public-client-id",
      code: "authorization-code-private",
      codeVerifier: "a".repeat(64),
      redirectUri: "http://localhost:43123",
    })).rejects.toThrow(/Mail.ReadWrite/i);
  });
});
