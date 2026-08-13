import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("canonical consumer first-run journey", () => {
  it("loads after the mature consumer surfaces and contains all eight milestone steps", () => {
    const scripts = read("server/src/api/dashboardScripts.ts");
    const source = read("web/consumer-onboarding.js");
    expect(scripts.indexOf('"/consumer-product.js"')).toBeLessThan(scripts.indexOf('"/consumer-onboarding.js"'));
    for (const id of [
      "account_ready",
      "mailbox_connected",
      "permissions_reviewed",
      "first_scan_completed",
      "sensitivity_chosen",
      "continuous_protection_configured",
      "family_option_reviewed",
      "consumer_home_ready",
    ]) expect(source).toContain(`'${id}'`);
    expect(source).toContain("Use local Scam Check");
    expect(source).toContain("Permission promise");
    expect(source).toContain("High Protection");
    expect(source).toContain("Balanced");
    expect(source).toContain("Low Noise");
  });

  it("credits security-relevant steps only from real observed or successful production state", () => {
    const source = read("web/consumer-onboarding.js");
    expect(source).toContain("#scanHistoryList .scan-history-status.completed");
    expect(source).toContain("backgroundToggle.getAttribute('aria-pressed') === 'true'");
    expect(source).toContain("/sensitivity`");
    expect(source).toContain("await readJson(await fetch(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/sensitivity`");
    expect(source).toContain("state.completed.add('sensitivity_chosen')");
    expect(source).toContain("Home cannot be marked ready until steps 1–7 are complete.");
    expect(source).not.toContain("state.completed.add('continuous_protection_configured');\n      await persistProgress(false)");
  });

  it("persists only privacy-safe progress and retires the legacy popup through its existing marker", () => {
    const source = read("web/consumer-onboarding.js");
    expect(source).toContain("const LEGACY_MARKER = 'consumer_intro'");
    expect(source).toContain("/onboarding`");
    expect(source).toContain("completedSteps");
    expect(source).not.toContain("localStorage");
    expect(source).not.toContain("sessionStorage");
    expect(source).not.toMatch(/https?:\/\/(?!example\.com)/);
    expect(source).not.toContain("mailbox body");
    expect(source).not.toContain("accessToken");
    expect(source).not.toContain("refreshToken");
  });

  it("keeps Family optional but never lets optional review bypass the required account, mailbox, scan, sensitivity or continuous-protection steps", () => {
    const source = read("web/consumer-onboarding.js");
    expect(source).toContain("Not now");
    expect(source).toContain("STEP_IDS.slice(0, 7).every");
    expect(source).toContain("if (facts.account) state.completed.add('account_ready')");
    expect(source).toContain("if (facts.mailbox) state.completed.add('mailbox_connected')");
    expect(source).toContain("if (facts.scanDone) state.completed.add('first_scan_completed')");
    expect(source).toContain("if (facts.backgroundEnabled) state.completed.add('continuous_protection_configured')");
  });
});
