import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const webRoot = join(import.meta.dirname, "../../web");
const learning = readFileSync(join(webRoot, "protection-learning.js"), "utf8");
const scan = readFileSync(join(webRoot, "scan-monitor.js"), "utf8");
const review = readFileSync(join(webRoot, "review-actions.js"), "utf8");
const scripts = readFileSync(join(import.meta.dirname, "../../server/src/api/dashboardScripts.ts"), "utf8");

describe("durable protection browser ownership", () => {
  it("loads the protection-learning module from the server-owned script composition", () => {
    expect(scripts).toContain('"/protection-learning.js"');
  });

  it("keeps Block under the canonical scan controller and sends only token plus explicit Family choice", () => {
    expect(scan).toContain("[data-action=\"block-sender\"],[data-action=\"block-domain\"]");
    expect(scan).toContain("emailShieldChooseFamilyBlockSharing");
    expect(scan).toContain("JSON.stringify({ token, shareWithFamily })");
    expect(scan).toContain("await policyChanged()");
    expect(scan).not.toMatch(/JSON\.stringify\(\{[^}]*address/s);
    expect(scan).not.toMatch(/JSON\.stringify\(\{[^}]*domain/s);
    expect(scan).not.toContain("unblock-sender");
    expect(scan).not.toContain("unblock-domain");
  });

  it("keeps Report Scam under the canonical review controller with account-local current and future Trash", () => {
    expect(review).toContain("[data-action=\"mark-safe\"],[data-action=\"trust-sender\"],[data-action=\"move-spam\"],[data-action=\"report-scam\"]");
    expect(review).toContain("JSON.stringify(isReportScam ? { token, blockSender } : { token })");
    expect(review).toContain("result.localProtected !== true");
    expect(review).toContain("Local campaign protection remains active");
    expect(review).toContain("The current message will be moved to Trash for this mailbox");
    expect(review).toContain("Future matching campaign mail will also be moved to Trash for this account");
    expect(review).toContain("result.movedCurrent === true");
    expect(review).toContain("current provider Trash move needs a retry");
    expect(review).toContain("One report cannot globally block a sender");
    expect(review).toContain("result.communityAccepted === true");
    expect(review).toContain("email-shield-family-changed");
    expect(review).toContain("await refreshPersonalPolicy()");
    expect(review).not.toContain("unblock-sender");
    expect(review).not.toContain("unblock-domain");
  });

  it("does not let protection-learning execute or suppress Block or Report Scam", () => {
    expect(learning).not.toContain("[data-action=\"block-sender\"]");
    expect(learning).not.toContain("[data-action=\"block-domain\"]");
    expect(learning).not.toContain("[data-action=\"report-scam\"]");
    expect(learning).not.toContain("event.stopImmediatePropagation()");
    expect(learning).not.toContain("unblock-sender");
    expect(learning).not.toContain("unblock-domain");
    expect(learning).toContain("emailShieldChooseFamilyBlockSharing");
    expect(learning).toContain("Cancel keeps the ${scope} block personal");
  });

  it("sends positive learning only after Safe or Trust succeeds", () => {
    expect(learning).toContain("Message marked Safe ✓");
    expect(learning).toContain("Sender trusted ✓");
    expect(learning).toContain("post(accountId, 'legitimate-feedback', { token })");
  });

  it("never serializes raw message content or provider message identity into learning calls", () => {
    for (const forbidden of ["textPreview", "htmlSignals", "providerNativeId", "messageId", "rawBody", "bodyText"]) {
      expect(learning).not.toContain(forbidden);
    }
  });
});