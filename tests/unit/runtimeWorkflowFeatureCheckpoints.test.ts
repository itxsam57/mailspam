import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

const expectedCheckpoints: Record<string, string[]> = {
  "web/ui-router.js": [
    "navigation.home.ui_confirmed",
    "navigation.scan.ui_confirmed",
    "navigation.protection.ui_confirmed",
    "navigation.family.ui_confirmed",
    "navigation.history.ui_confirmed",
    "navigation.account.ui_confirmed",
    "navigation.settings.ui_confirmed",
  ],
  "web/account-selection-state.js": ["account.select.ui_confirmed"],
  "web/account-disconnect.js": ["account.disconnect.ui_confirmed"],
  "web/background-protection.js": [
    "protection.background.toggle.ui_confirmed",
    "protection.background.interval.ui_confirmed",
  ],
  "web/scan-history.js": ["mailbox.scan.history.ui_confirmed", "mailbox.scan.resume.ui_confirmed"],
  "web/scan-monitor.js": [
    "mailbox.scan.quick.ui_confirmed",
    "mailbox.scan.full.ui_confirmed",
    "mailbox.scan.spam.ui_confirmed",
    "mailbox.scan.stop.ui_confirmed",
    "message.block_sender.ui_confirmed",
    "message.block_domain.ui_confirmed",
    "message.trash.ui_confirmed",
  ],
  "web/account-plan.js": [
    "account.profile.snapshot.ui_confirmed",
    "account.profile.register.ui_confirmed",
    "account.profile.sign_in.ui_confirmed",
    "account.recovery.open.ui_confirmed",
    "account.mailbox.link.ui_confirmed",
    "account.sign_out.ui_confirmed",
    "account.devices.revoke.ui_confirmed",
  ],
  "web/account-lifecycle.js": [
    "account.recovery.rotate.ui_confirmed",
    "account.devices.revoke_others.ui_confirmed",
    "account.metadata.export.ui_confirmed",
    "account.sign_out_everywhere.ui_confirmed",
    "family.transfer.ui_confirmed",
    "account.family.delete.ui_confirmed",
    "account.delete.ui_confirmed",
  ],
  "web/family-shield.js": [
    "family.load.ui_confirmed",
    "family.create.ui_confirmed",
    "family.join.ui_confirmed",
    "family.invite.ui_confirmed",
    "family.strict.ui_confirmed",
    "family.leave.ui_confirmed",
    "family.remove_member.ui_confirmed",
  ],
  "web/family-guardian-preferences.js": ["family.guardian_preferences.ui_confirmed"],
  "web/policy-management.js": [
    "policy.load.ui_confirmed",
    "policy.revoke.ui_confirmed",
    "policy.bulk_revoke.ui_confirmed",
    "policy.clear.ui_confirmed",
    "policy.reset.ui_confirmed",
    "policy.selection.toggle.ui_confirmed",
  ],
  "web/consumer-product.js": [
    "mailbox.health.run.ui_confirmed",
    "mailbox.health.load.ui_confirmed",
    "activity.load.ui_confirmed",
    "activity.clear.ui_confirmed",
    "family.load.ui_confirmed",
    "browser_destination.check.ui_confirmed",
    "intervention.check.ui_confirmed",
    "exposure.email.check.ui_confirmed",
    "support.bundle.export.ui_confirmed",
    "onboarding.complete.ui_confirmed",
    "mailbox.cleanup.ui_confirmed",
    "message.undo.ui_confirmed",
  ],
  "web/scam-check.js": ["scam_check.run.ui_confirmed", "scam_check.clear.ui_confirmed"],
  "web/shopping-safety.js": ["shopping_safety.run.ui_confirmed"],
  "web/media-authenticity.js": ["media_authenticity.run.ui_confirmed"],
  "web/billing-plan-ui.js": [
    "billing.plan.load.ui_confirmed",
    "billing.purchase.individual.ui_confirmed",
    "billing.purchase.family.ui_confirmed",
    "billing.purchase.restore.ui_confirmed",
  ],
  "web/operations-dashboard.js": ["community.operations.load.ui_confirmed"],
  "web/unsubscribe-monitor.js": ["message.unsubscribe.ui_confirmed"],
  "web/analyze-links-actions.js": ["message.analyze_links.ui_confirmed"],
  "web/review-actions.js": [
    "message.report_scam.ui_confirmed",
    "message.move_spam.ui_confirmed",
    "message.mark_safe.ui_confirmed",
    "message.trust_sender.ui_confirmed",
  ],
};

describe("feature-owner runtime workflow checkpoints", () => {
  it("keeps visible completion evidence in the authoritative feature module", () => {
    const missing: string[] = [];
    for (const [path, checkpoints] of Object.entries(expectedCheckpoints)) {
      const source = read(path);
      for (const checkpoint of checkpoints) {
        if (!source.includes(`checkpoint('${checkpoint}'`) && !source.includes(`checkpoint(\"${checkpoint}\"`)) {
          missing.push(`${path}: ${checkpoint}`);
        }
      }
    }
    expect(missing).toEqual([]);
  });

  it("registers current dynamic buttons that otherwise have no semantic data contract", () => {
    const accountPlan = read("web/account-plan.js");
    const family = read("web/family-shield.js");
    const consumer = read("web/consumer-product.js");
    const history = read("web/scan-history.js");
    const disconnect = read("web/account-disconnect.js");

    expect(accountPlan).toContain("registerControl(revoke, 'account.devices.revoke'");
    expect(family).toContain("registerControl(remove, 'family.remove_member'");
    expect(consumer).toContain("registerControl(cleanup, 'mailbox.cleanup'");
    expect(consumer).toContain("registerControl(undo, 'message.undo'");
    expect(history).toContain("registerControl(resumeScanButton, 'mailbox.scan.resume'");
    expect(disconnect).toContain("registerControl(button, 'account.disconnect'");
  });
});
