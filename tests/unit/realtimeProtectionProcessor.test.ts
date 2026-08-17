import { describe, expect, it } from "vitest";
import type { AccountSession, SessionStore } from "../../server/src/api/sessionStore.js";
import {
  RealtimeProtectionProcessor,
  RealtimeProtectionRunError,
} from "../../server/src/realtime/realtimeProtectionProcessor.js";
import type { CanonicalInboundEventV1 } from "../../server/src/realtime/inboundEvents.js";

function session(accountKey = "a".repeat(64), provider: "gmail" | "outlook" = "gmail", active = false): AccountSession {
  return {
    id: `session-${provider}`,
    provider,
    label: "fixture",
    config: provider === "gmail"
      ? { provider: "gmail", mode: "fixture", fixtureFolderOverrides: {} }
      : { provider: "outlook", mode: "fixture", fixtureFolderOverrides: {} },
    activeScanWorker: active ? ({} as AccountSession["activeScanWorker"]) : null,
    personalPolicy: {} as AccountSession["personalPolicy"],
    policyAccountKey: accountKey,
    vaultReferences: [],
    closing: false,
    unsubscribeActions: new Map(),
    reviewActions: new Map(),
  };
}

function canonicalSession(account: AccountSession | undefined): Pick<SessionStore, "canonicalForPolicyAccountKey"> {
  return {
    canonicalForPolicyAccountKey: (accountKey) => account?.policyAccountKey === accountKey ? account : undefined,
  };
}

function event(overrides: Partial<CanonicalInboundEventV1> = {}): CanonicalInboundEventV1 {
  return {
    schemaVersion: 1,
    accountKey: "a".repeat(64),
    provider: "gmail",
    source: "push",
    kind: "mailbox_changed",
    eventId: "provider-event-1",
    checkpoint: "42",
    providerMessageId: null,
    ...overrides,
  };
}

describe("RealtimeProtectionProcessor", () => {
  it("uses the shared bounded executor and maps Review + Unknown into realtime warnings", async () => {
    const account = session();
    const calls: AccountSession[] = [];
    const processor = new RealtimeProtectionProcessor(
      canonicalSession(account),
      {
        executeWithSummary: async (value) => {
          calls.push(value);
          return { examined: 8, review: 2, highRisk: 1, confirmedThreat: 1, unknown: 1 };
        },
      },
    );

    await expect(processor.process(event())).resolves.toEqual({
      examined: 8,
      warnings: 3,
      highRisk: 1,
      confirmedThreat: 1,
    });
    expect(calls).toEqual([account]);
  });

  it("does not let webhook metadata choose a different connected account", async () => {
    const processor = new RealtimeProtectionProcessor(
      canonicalSession(session("b".repeat(64))),
      { executeWithSummary: async () => ({ examined: 0, review: 0, highRisk: 0, confirmedThreat: 0, unknown: 0 }) },
    );
    await expect(processor.process(event())).rejects.toMatchObject({ code: "provider_unavailable" });
  });

  it("fails closed when the bound account provider does not match the trigger provider", async () => {
    const processor = new RealtimeProtectionProcessor(
      canonicalSession(session("a".repeat(64), "outlook")),
      { executeWithSummary: async () => ({ examined: 0, review: 0, highRisk: 0, confirmedThreat: 0, unknown: 0 }) },
    );
    await expect(processor.process(event())).rejects.toMatchObject({ code: "provider_mismatch" });
  });

  it("rejects ambiguous canonical ownership rather than scanning an arbitrary session", async () => {
    let called = false;
    const processor = new RealtimeProtectionProcessor(
      {
        canonicalForPolicyAccountKey: () => {
          throw new Error("Mailbox session ownership is ambiguous; reconnect this mailbox before protection continues.");
        },
      },
      { executeWithSummary: async () => { called = true; return { examined: 0, review: 0, highRisk: 0, confirmedThreat: 0, unknown: 0 }; } },
    );
    await expect(processor.process(event())).rejects.toBeInstanceOf(RealtimeProtectionRunError);
    await expect(processor.process(event())).rejects.toMatchObject({ code: "provider_mismatch" });
    expect(called).toBe(false);
  });

  it("does not acknowledge a trigger while a manual/scheduled scan owns the account Worker slot", async () => {
    let called = false;
    const processor = new RealtimeProtectionProcessor(
      canonicalSession(session("a".repeat(64), "gmail", true)),
      { executeWithSummary: async () => { called = true; return { examined: 0, review: 0, highRisk: 0, confirmedThreat: 0, unknown: 0 }; } },
    );
    await expect(processor.process(event())).rejects.toMatchObject({ code: "scan_conflict" });
    expect(called).toBe(false);
  });

  it("does not use providerMessageId as a shortcut around the shared mailbox protection path", async () => {
    const account = session();
    let calls = 0;
    const processor = new RealtimeProtectionProcessor(
      canonicalSession(account),
      {
        executeWithSummary: async () => {
          calls++;
          return { examined: 1, review: 0, highRisk: 0, confirmedThreat: 1, unknown: 0 };
        },
      },
    );
    await processor.process(event({ kind: "message_arrived", providerMessageId: "remote-message-id" }));
    expect(calls).toBe(1);
  });
});