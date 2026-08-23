import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import type { AccountSession } from "../../server/src/api/sessionStore.js";
import { InMemoryInboundEventStateRepository } from "../../server/src/realtime/inboundEvents.js";
import { RealtimeProtectionService } from "../../server/src/realtime/realtimeProtectionService.js";

function session(accountKey: string): AccountSession {
  return {
    id: `session-${accountKey.slice(0, 6)}`,
    provider: "gmail",
    label: "fixture",
    config: { provider: "gmail", mode: "fixture", fixtureFolderOverrides: {} },
    activeScanWorker: null,
    personalPolicy: {} as AccountSession["personalPolicy"],
    policyAccountKey: accountKey,
    vaultReferences: [],
    closing: false,
    unsubscribeActions: new Map(),
    reviewActions: new Map(),
  } as AccountSession;
}

function service(options: Record<string, unknown>): RealtimeProtectionService {
  return new RealtimeProtectionService(options as never);
}

describe("final consumer closure contracts", () => {
  it("authorizes automatic changed-mailbox scans with the persisted continuous-protection state", async () => {
    const account = session("a".repeat(64));
    let enabled = false;
    let checkpoint = "checkpoint-1";
    let processed = 0;
    const realtime = service({
      sessions: { list: () => [account] },
      repository: new InMemoryInboundEventStateRepository(),
      pollProbe: { checkpoint: async () => checkpoint },
      protectionEnabled: (accountKey: string) => accountKey === account.policyAccountKey && enabled,
      processor: {
        process: async () => {
          processed += 1;
          return { examined: 1, warnings: 0, highRisk: 0, confirmedThreat: 0 };
        },
      },
    });

    await realtime.pollNow(1_000);
    checkpoint = "checkpoint-2";
    await realtime.pollNow(2_000);
    expect(processed).toBe(0);

    enabled = true;
    await realtime.pollNow(3_000);
    expect(processed).toBe(0);
    checkpoint = "checkpoint-3";
    await realtime.pollNow(4_000);
    expect(processed).toBe(1);
  });

  it("rejects push or idle automatic processing while continuous protection is disabled", async () => {
    let enabled = false;
    let processed = 0;
    const realtime = service({
      sessions: { list: () => [] },
      repository: new InMemoryInboundEventStateRepository(),
      protectionEnabled: () => enabled,
      processor: {
        process: async () => {
          processed += 1;
          return { examined: 1, warnings: 0, highRisk: 0, confirmedThreat: 0 };
        },
      },
    });
    const event = {
      schemaVersion: 1 as const,
      accountKey: "b".repeat(64),
      provider: "gmail" as const,
      source: "push" as const,
      kind: "mailbox_changed" as const,
      eventId: "push-disabled-1",
      checkpoint: "99",
      providerMessageId: null,
    };

    expect((await realtime.enqueue(event) as { status: string }).status).toBe("disabled");
    expect(processed).toBe(0);
    enabled = true;
    expect((await realtime.enqueue({ ...event, eventId: "push-enabled-2", checkpoint: "100" }) as { status: string }).status).toBe("processed");
    expect(processed).toBe(1);
  });

  it("presents one coherent consumer workflow instead of unsupported promises", () => {
    const onboarding = readFileSync(new URL("../../web/consumer-onboarding.js", import.meta.url), "utf8");
    const background = readFileSync(new URL("../../web/background-protection.js", import.meta.url), "utf8");
    const product = readFileSync(new URL("../../web/consumer-product.js", import.meta.url), "utf8");
    const scripts = readFileSync(new URL("../../server/src/api/dashboardScripts.ts", import.meta.url), "utf8");
    const billing = readFileSync(new URL("../../web/billing-plan-ui.js", import.meta.url), "utf8");

    // EMA-26: the promised workflow lands on actual controls, including a truthful zero-mailbox state.
    expect(onboarding).toContain("route('settings')");
    expect(onboarding).toContain("Continuous Protection");
    expect(background).toContain("Connect or select a mailbox to configure continuous protection.");
    expect(background).toContain("Provider-event protection");
    expect(background).toContain("metadata checkpoint fallback");

    // EMA-27 + EMA-30: review surfaces are available before mailbox authorization; entitlement remains separate.
    expect(onboarding).toContain("Review provider permissions before connecting a mailbox");
    expect(onboarding).toContain("Gmail: OpenID identity + Gmail modify access");
    expect(onboarding).toContain("Microsoft: identity + Mail.ReadWrite");
    expect(onboarding).toContain("Family Shield can be reviewed before mailbox setup");
    expect(onboarding).toContain("A paid Family entitlement is still required to create or join protected Family state");

    // EMA-28 + EMA-29 are regression contracts: mailbox-scoped work must stay mailbox-scoped.
    expect(onboarding).toContain("requestMailboxSetup('scan')");
    expect(onboarding).toContain("route('scan')");
    expect(onboarding).toContain("requestMailboxSetup('sensitivity')");
    expect(onboarding).toContain("/sensitivity");

    // EMA-12/22: do not advertise a setting or detector the release cannot actually deliver.
    expect(product).not.toContain("consumerRicherNotifications");
    expect(product).not.toContain("Notification privacy");
    expect(scripts).not.toContain('"/media-authenticity.js"');

    // EMA-13: Activity has accessible privacy-safe disclosure, without exposing reversible identifiers.
    expect(product).toContain("data-activity-details");
    expect(product).toContain("Why Email Shield recorded this");
    expect(product).toContain("undoAvailable");

    // EMA-24: Restore always reaches a generation-owned, diagnostic terminal state.
    expect(billing).toContain("restoreGeneration");
    expect(billing).toContain("nothing_to_restore");
    expect(billing).toContain("verification_rejected");
    expect(billing).toContain("billing.purchase.restore.ui_confirmed");
  });
});
