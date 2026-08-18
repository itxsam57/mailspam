import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const browser = readFileSync(new URL("../../web/local-security.js", import.meta.url), "utf8");

describe("EMA-8 generic local-security transport isolation", () => {
  it("does not infer semantic message-action consumption from a successful protected fetch", () => {
    expect(browser).not.toContain("function disableUsedAction(");
    expect(browser).not.toContain("requestActionToken(init)");
    expect(browser).not.toContain("disableUsedAction(token)");
    expect(browser).not.toContain("data-review-token");
    expect(browser).not.toContain("data-unsubscribe-token");
  });

  it("preserves transport security responsibilities without becoming a message-action owner", () => {
    expect(browser).toContain("X-Email-Shield-CSRF");
    expect(browser).toContain("X-Email-Shield-Nonce");
    expect(browser).toContain("mutationNonce()");
    expect(browser).toContain("email-shield-session-expired");
    expect(browser).toContain("response.status === 401");
  });
});
