import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { analyzeMailboxHealth, type IdentitySecurityPort } from "../../server/src/consumer/mailboxHealth.js";

const checkedSecurityPort: IdentitySecurityPort = {
  async inspect(provider) {
    return {
      provider,
      checkedAt: "2026-08-20T12:00:00.000Z",
      checks: (["forwarding_rules", "inbox_rules", "delegates_send_as", "connected_apps_sessions"] as const).map((id) => ({
        id,
        state: "checked" as const,
        detail: "Checked in test.",
        indicators: [],
      })),
    };
  },
};

function providerAlert(input: {
  nativeId: string;
  subject: string;
  preview: string;
  date?: string;
  messageId?: string;
}): CanonicalEnvelope {
  const date = input.date ?? "2026-08-20T12:00:00.000Z";
  return {
    provider: "gmail",
    accountProof: "account-proof",
    messageId: input.messageId ?? `message-${input.nativeId}`,
    providerNativeId: input.nativeId,
    folder: "inbox",
    providerFolderName: "INBOX",
    from: {
      displayName: "Google",
      address: "no-reply@accounts.google.com",
      domain: "accounts.google.com",
    },
    replyTo: null,
    subject: input.subject,
    date,
    authentication: {
      providerTrust: "trusted",
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      arc: "none",
    },
    textPreview: input.preview,
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: {
      isFirstContact: false,
      threadContinuityBroken: false,
      replyToChangedMidThread: false,
    },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: {
      fetchedAt: date,
      sizeBytes: 900,
      encoding: "plain",
      contentCoverage: "complete",
    },
  };
}

function securityAlerts(report: Awaited<ReturnType<typeof analyzeMailboxHealth>>) {
  return report.indicators.filter((indicator) => indicator.code === "TRUSTED_PROVIDER_SECURITY_ALERT");
}

describe("EMA-17 authenticated provider security-alert composition", () => {
  it("does not inflate warning cards when the same provider-native alert is observed more than once", async () => {
    const duplicate = providerAlert({
      nativeId: "provider-alert-1",
      subject: "Security alert: new sign-in",
      preview: "A new sign-in was detected on your account.",
    });

    const report = await analyzeMailboxHealth({
      provider: "gmail",
      envelopes: [duplicate, { ...duplicate, messageId: "duplicate-listing-copy" }],
      securityPort: checkedSecurityPort,
    });

    expect(report.state).toBe("attention");
    expect(securityAlerts(report)).toHaveLength(1);
  });

  it("keeps genuinely distinct authenticated alert classes visible without rendering indistinguishable warning cards", async () => {
    const report = await analyzeMailboxHealth({
      provider: "gmail",
      envelopes: [
        providerAlert({
          nativeId: "provider-alert-signin",
          subject: "Security alert: new sign-in",
          preview: "A new sign-in was detected on your account.",
          date: "2026-08-20T11:00:00.000Z",
        }),
        providerAlert({
          nativeId: "provider-alert-password",
          subject: "Password changed",
          preview: "Your account password changed recently.",
          date: "2026-08-20T12:00:00.000Z",
        }),
      ],
      securityPort: checkedSecurityPort,
    });

    const alerts = securityAlerts(report);
    expect(report.state).toBe("attention");
    expect(alerts).toHaveLength(2);
    expect(new Set(alerts.map((alert) => `${alert.title}\n${alert.detail}`)).size).toBe(2);
    for (const alert of alerts) {
      expect(alert.detail).toMatch(/official app|official website|official site/i);
      expect(alert.detail).not.toMatch(/Security alert: new sign-in|Password changed/);
    }
  });

  it("groups several distinct alerts of the same class into one counted consumer warning", async () => {
    const report = await analyzeMailboxHealth({
      provider: "gmail",
      envelopes: [
        providerAlert({
          nativeId: "provider-alert-signin-a",
          subject: "Security alert: new sign-in",
          preview: "A new sign-in was detected on your account.",
          date: "2026-08-20T10:00:00.000Z",
        }),
        providerAlert({
          nativeId: "provider-alert-signin-b",
          subject: "New sign-in on your account",
          preview: "Security alert for a new sign-in.",
          date: "2026-08-20T12:00:00.000Z",
        }),
      ],
      securityPort: checkedSecurityPort,
    });

    const alerts = securityAlerts(report);
    expect(report.state).toBe("attention");
    expect(alerts).toHaveLength(1);
    expect(alerts[0]?.title).toMatch(/new sign-in/i);
    expect(alerts[0]?.detail).toMatch(/2 (?:distinct )?authenticated/i);
    expect(alerts[0]?.detail).toMatch(/official app|official website|official site/i);
    expect(alerts[0]?.observedAt).toBe("2026-08-20T12:00:00.000Z");
  });
});
