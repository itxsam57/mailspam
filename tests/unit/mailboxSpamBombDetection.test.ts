import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { analyzeMailboxHealth, type IdentitySecurityPort } from "../../server/src/consumer/mailboxHealth.js";

const checkedSecurityPort: IdentitySecurityPort = {
  async inspect(provider) {
    return {
      provider,
      checkedAt: "2026-08-13T12:00:00.000Z",
      checks: (["forwarding_rules", "inbox_rules", "delegates_send_as", "connected_apps_sessions"] as const).map((id) => ({
        id,
        state: "checked" as const,
        detail: "Checked in test.",
        indicators: [],
      })),
    };
  },
};

function envelope(index: number, date: string, options: { firstContact?: boolean; sender?: string } = {}): CanonicalEnvelope {
  const sender = options.sender ?? `sender-${index}@new-sender-${index}.example`;
  const domain = sender.split("@")[1] ?? "example.test";
  return {
    provider: "gmail",
    accountProof: "proof",
    messageId: `message-${index}`,
    providerNativeId: `native-${index}`,
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: `Sender ${index}`, address: sender, domain },
    replyTo: null,
    subject: `Routine message ${index}`,
    date,
    authentication: { providerTrust: "trusted", spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview: "Ordinary message content.",
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: {
      isFirstContact: options.firstContact ?? true,
      threadContinuityBroken: false,
      replyToChangedMidThread: false,
    },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: {
      fetchedAt: date,
      sizeBytes: 500,
      encoding: "plain",
      contentCoverage: "complete",
    },
  };
}

describe("spam-bomb security-alert hiding detection", () => {
  it("warns on a dense burst from many distinct first-contact senders", async () => {
    const start = Date.parse("2026-08-13T12:00:00.000Z");
    const envelopes = Array.from({ length: 35 }, (_, index) => envelope(index, new Date(start + index * 20_000).toISOString()));
    const report = await analyzeMailboxHealth({
      provider: "gmail",
      envelopes,
      securityPort: checkedSecurityPort,
    });

    expect(report.state).toBe("attention");
    expect(report.indicators).toContainEqual(expect.objectContaining({
      code: "FIRST_CONTACT_MESSAGE_FLOOD",
      severity: "warning",
      title: "Message flood may hide a security alert",
      provenance: "mailbox_observation",
    }));
    const flood = report.indicators.find((item) => item.code === "FIRST_CONTACT_MESSAGE_FLOOD")!;
    expect(flood.detail).toMatch(/35 messages|distinct first-contact senders/i);
    expect(flood.detail).toMatch(/official security and recent-activity pages directly/i);
  });

  it("does not warn when the same volume is spread out over hours", async () => {
    const start = Date.parse("2026-08-13T06:00:00.000Z");
    const envelopes = Array.from({ length: 35 }, (_, index) => envelope(index, new Date(start + index * 10 * 60_000).toISOString()));
    const report = await analyzeMailboxHealth({ provider: "gmail", envelopes, securityPort: checkedSecurityPort });
    expect(report.indicators.map((item) => item.code)).not.toContain("FIRST_CONTACT_MESSAGE_FLOOD");
    expect(report.state).toBe("healthy_observed");
  });

  it("does not confuse repeated mail from one established sender with a spam bomb", async () => {
    const start = Date.parse("2026-08-13T12:00:00.000Z");
    const envelopes = Array.from({ length: 40 }, (_, index) => envelope(index, new Date(start + index * 10_000).toISOString(), {
      firstContact: false,
      sender: "alerts@known-service.example",
    }));
    const report = await analyzeMailboxHealth({ provider: "gmail", envelopes, securityPort: checkedSecurityPort });
    expect(report.indicators.map((item) => item.code)).not.toContain("FIRST_CONTACT_MESSAGE_FLOOD");
    expect(report.state).toBe("healthy_observed");
  });
});
