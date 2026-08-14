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

  it("credits security-relevant steps only from account-authoritative production state", () => {
    const source = read("web/consumer-onboarding.js");
    expect(source).toContain("/scan-history`");
    expect(source).toContain("/background-protection`");
    expect(source).toContain("scanHistory.history.some((record) => record?.status === 'completed')");
    expect(source).toContain("background?.enabled === true");
    expect(source).toContain("/sensitivity`");
    expect(source).toContain("await readJson(await fetch(`/api/consumer/v1/accounts/${encodeURIComponent(id)}/sensitivity`");
    expect(source).toContain("state.completed.add('sensitivity_chosen')");
    expect(source).toContain("Home cannot be marked ready until steps 1–7 are complete.");
    expect(source).not.toContain("#scanHistoryList .scan-history-status.completed");
    expect(source).not.toContain("backgroundToggle.getAttribute('aria-pressed') === 'true'");
  });

  it("keeps completed first-scan credit monotonic even when bounded scan history no longer contains the original record", () => {
    const source = read("web/consumer-onboarding.js");
    expect(source).toContain("completed.add('first_scan_completed')");
    expect(source).toContain("monotonic historical milestone");
    expect(source).not.toContain("else completed.delete('first_scan_completed')");
  });

  it("replaces rather than accumulates mailbox onboarding state and refuses cross-account writes", () => {
    const source = read("web/consumer-onboarding.js");
    expect(source).toContain("mailboxId: null");
    expect(source).toContain("state.completed = new Set()");
    expect(source).toContain("state.completed = completed");
    expect(source).toContain("state.mailboxId = requestedMailboxId");
    expect(source).toContain("activeMailboxId() !== requestedMailboxId");
    expect(source).toContain("state.mailboxId !== expectedMailboxId || activeId !== expectedMailboxId");
    expect(source).toContain("Mailbox selection changed. Setup state was refreshed without copying progress between accounts.");
    expect(source).toContain("refreshQueued");
    expect(source).not.toContain("for (const step of saved) if (STEP_IDS.includes(step)) state.completed.add(step)");
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
    expect(source).toContain("if (state.profileSignedIn) state.completed.add('account_ready')");
    expect(source).toContain("state.completed.add('mailbox_connected')");
    expect(source).toContain("completed.add('first_scan_completed')");
    expect(source).toContain("completed.add('continuous_protection_configured')");
  });
});