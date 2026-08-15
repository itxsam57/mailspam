import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("Report Scam action separation", () => {
  it("never lets the Report Scam API own a provider Trash move", () => {
    const source = readFileSync(new URL("../../server/src/api/protectionActions.ts", import.meta.url), "utf8");
    const start = source.indexOf('app.post("/api/accounts/:id/messages/report-scam"');
    const end = source.indexOf('app.post("/api/accounts/:id/messages/legitimate-feedback"', start);
    expect(start).toBeGreaterThanOrEqual(0);
    expect(end).toBeGreaterThan(start);
    const route = source.slice(start, end);
    expect(route).not.toContain("moveCurrentMessageToTrash(");
    expect(route).toContain('movedCurrent: false');
    expect(route).toContain('providerAction: "none"');
  });

  it("tells the user that reporting does not move mail and keeps Trash/Spam explicit", () => {
    const source = readFileSync(new URL("../../web/review-actions.js", import.meta.url), "utf8");
    expect(source).toContain("Reporting does not move the current message; Trash and Spam/Junk remain separate explicit actions.");
    expect(source).toContain("The current message was not moved. Use the separate Trash or Move to Spam/Junk action");
    expect(source).not.toContain("attempting current-message Trash");
    expect(source).not.toContain("Scam campaign protected locally and current message moved to Trash");
  });
});
