import { describe, expect, it } from "vitest";
import { campaignRadar } from "../../server/src/consumer/familyGuardian.js";

describe("campaign radar emerging-wave signals", () => {
  it("ranks recent high-velocity independent reports ahead of older steady campaigns", () => {
    const now = Date.parse("2026-08-13T12:00:00.000Z");
    const radar = campaignRadar([
      {
        type: "campaign",
        value: "a".repeat(64),
        confirmedThreat: false,
        ruleId: "older-steady",
        independentReports: 5,
        firstSeen: "2026-07-20T12:00:00.000Z",
        lastSeen: "2026-08-10T12:00:00.000Z",
      },
      {
        type: "campaign",
        value: "b".repeat(64),
        confirmedThreat: false,
        ruleId: "new-fast",
        independentReports: 4,
        firstSeen: "2026-08-13T10:00:00.000Z",
        lastSeen: "2026-08-13T11:30:00.000Z",
      },
    ], now);

    expect(radar.available).toBe(true);
    expect(radar.scope).toBe("network_wide");
    expect(radar.advisories.map((item) => item.ruleId)).toEqual(["new-fast", "older-steady"]);
    expect(radar.advisories[0]).toMatchObject({
      novelty: "new",
      momentum: "rapid",
      severity: "warning",
      independentReports: 4,
    });
    expect(radar.advisories[0]!.reportRatePerDay).toBeGreaterThan(6);
    expect(radar.advisories[0]!.warningPattern).toMatch(/Emerging campaign pattern/i);
    expect(radar.advisories[0]!.guidance).toMatch(/independently obtained official channel/i);
    expect(radar.advisories[1]).toMatchObject({ novelty: "established", momentum: "steady" });
  });

  it("does not infer momentum from malformed signed timestamps", () => {
    const radar = campaignRadar([
      {
        type: "campaign",
        value: "c".repeat(64),
        confirmedThreat: false,
        ruleId: "bad-time",
        independentReports: 2,
        firstSeen: "not-a-time",
        lastSeen: "also-not-a-time",
      },
    ], Date.parse("2026-08-13T12:00:00.000Z"));

    expect(radar.advisories[0]).toMatchObject({
      novelty: "unknown",
      momentum: "unknown",
      reportRatePerDay: null,
      severity: "watch",
    });
  });

  it("never reconstructs private examples in its sanitized warning template", () => {
    const radar = campaignRadar([
      {
        type: "campaign",
        value: "d".repeat(64),
        confirmedThreat: true,
        ruleId: "confirmed-wave",
        independentReports: 8,
        firstSeen: "2026-08-13T08:00:00.000Z",
        lastSeen: "2026-08-13T11:00:00.000Z",
      },
    ], Date.parse("2026-08-13T12:00:00.000Z"));

    const serialized = JSON.stringify(radar);
    expect(radar.advisories[0]).toMatchObject({ severity: "confirmed" });
    expect(serialized).not.toMatch(/senderAddress|mailboxAddress|subject|message body|reporter identity|precise location/i);
  });
});
