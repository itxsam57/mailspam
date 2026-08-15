import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("Report Scam account-local disposal", () => {
  it("moves the reported message to Trash after the durable local campaign rule is saved", () => {
    const source = readFileSync(new URL("../../server/src/api/protectionActions.ts", import.meta.url), "utf8");
    const start = source.indexOf('app.post("/api/accounts/:id/messages/report-scam"');
    const end = source.indexOf('app.post("/api/accounts/:id/messages/legitimate-feedback"', start);
    expect(start).toBeGreaterThanOrEqual(0);
    expect(end).toBeGreaterThan(start);
    const route = source.slice(start, end);
    const policyIndex = route.indexOf("policy.reportCampaign(action.communityReport.campaignFingerprint)");
    const moveIndex = route.indexOf("moveCurrentMessageToTrash(");
    expect(policyIndex).toBeGreaterThanOrEqual(0);
    expect(moveIndex).toBeGreaterThan(policyIndex);
    expect(route).toContain("movedCurrent: move.movedCurrent");
    expect(route).toContain('providerAction: move.movedCurrent ? "trash" : "trash_pending"');
  });

  it("keeps the community threshold independent while telling the user about account-local Trash", () => {
    const source = readFileSync(new URL("../../web/review-actions.js", import.meta.url), "utf8");
    expect(source).toContain("The current message will be moved to Trash for this mailbox");
    expect(source).toContain("Future matching campaign mail will also be moved to Trash for this account");
    expect(source).toContain("One report cannot globally block a sender");
    expect(source).not.toContain("Reporting does not move the current message");
    expect(source).not.toContain("The current message was not moved");
  });
});
