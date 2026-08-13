import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { messageIntentLayer } from "../../server/src/engine/layers/messageIntent.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";
import { evaluateSubmittedImage, type VisualTextExtractor } from "../../server/src/consumer/scamCheckInputs.js";

const require = createRequire(import.meta.url);
const pngModule = require("pngjs") as {
  PNG: {
    new (options: { width: number; height: number }): { data: Buffer; width: number; height: number };
    sync: { write: (image: { data: Buffer; width: number; height: number }) => Buffer };
  };
};

const emptyDeps = {
  personalPolicy: new InMemoryPersonalPolicyStore(),
  threatFeed: { getVerifiedEntries: () => [] },
};

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  return {
    provider: "gmail",
    accountProof: "workstream-u-proof",
    messageId: "workstream-u-message",
    providerNativeId: "workstream-u-native",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: {
      displayName: "Example Organization",
      address: "notice@example.test",
      domain: "example.test",
    },
    replyTo: null,
    subject: "Routine notification",
    date: "2026-08-13T12:00:00.000Z",
    authentication: { providerTrust: "trusted", spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview: "Routine authenticated message with no urgent request.",
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: {
      fetchedAt: "2026-08-13T12:00:00.000Z",
      sizeBytes: 1200,
      encoding: "plain",
      contentCoverage: "complete",
    },
    ...overrides,
  };
}

function codesFromIntent(value: CanonicalEnvelope): string[] {
  return messageIntentLayer(value).evidence.map((item) => item.code);
}

function codesFromScan(value: CanonicalEnvelope): string[] {
  return scanMessage(value, emptyDeps).scored.evidence.map((item) => item.code);
}

function onePixelPng(): Buffer {
  const image = new pngModule.PNG({ width: 1, height: 1 });
  image.data[0] = 255;
  image.data[1] = 255;
  image.data[2] = 255;
  image.data[3] = 255;
  return pngModule.PNG.sync.write(image);
}

describe("Workstream U adversarial scenario closure", () => {
  it("detects a malicious calendar invitation only when the invite is paired with a sensitive action", () => {
    const malicious = envelope({
      from: { displayName: "Calendar Service", address: "invite@calendar-alerts.example", domain: "calendar-alerts.example" },
      subject: "Calendar invitation: Payroll review",
      textPreview: "You were invited to a meeting. Sign in to view the invitation and verify your account before it expires.",
      authentication: { providerTrust: "trusted", spf: "fail", dkim: "fail", dmarc: "fail", arc: "none" },
    });
    expect(codesFromIntent(malicious)).toContain("CALENDAR_INVITE_SCAM_INTENT");
    expect(scanMessage(malicious, emptyDeps).scored.verdict).not.toBe("safe");

    const legitimate = envelope({
      from: { displayName: "Company Calendar", address: "calendar@example.test", domain: "example.test" },
      subject: "Calendar invitation: Q3 planning meeting",
      textPreview: "You are invited to the Q3 planning meeting on Thursday at 10:00. The agenda is attached to the event.",
    });
    expect(codesFromIntent(legitimate)).not.toContain("CALENDAR_INVITE_SCAM_INTENT");
    expect(scanMessage(legitimate, emptyDeps).scored.verdict).toBe("safe");
  });

  it("detects forced browser-extension/download lures without flagging an optional official-store update", () => {
    const malicious = envelope({
      from: { displayName: "Document Viewer", address: "notice@viewer-download.example", domain: "viewer-download.example" },
      subject: "Security document requires browser extension",
      textPreview: "Install this Chrome extension now. It is required to view the protected document. Download and run the security tool to continue.",
      authentication: { providerTrust: "trusted", spf: "fail", dkim: "fail", dmarc: "fail", arc: "none" },
    });
    expect(codesFromIntent(malicious)).toContain("BROWSER_EXTENSION_DOWNLOAD_LURE");
    expect(scanMessage(malicious, emptyDeps).scored.verdict).not.toBe("safe");

    const legitimate = envelope({
      subject: "Optional browser extension update available",
      textPreview: "Our optional Chrome extension has a new version. You may update it later from the official browser store; no action is required.",
    });
    expect(codesFromIntent(legitimate)).not.toContain("BROWSER_EXTENSION_DOWNLOAD_LURE");
    expect(scanMessage(legitimate, emptyDeps).scored.verdict).toBe("safe");
  });

  it("detects polished credential phishing without relying on spelling or grammar mistakes", () => {
    const polished = envelope({
      from: { displayName: "Account Security", address: "security@account-review.example", domain: "account-review.example" },
      subject: "Security review required",
      textPreview: "We detected unusual sign-in activity. Please verify your account within 24 hours by entering your password and one-time passcode. If you do not complete the review, the account will be suspended.",
      links: [{
        visibleText: "Review security settings",
        rawUrl: "https://account-review.example/security",
        normalizedUrl: "https://account-review.example/security",
        claimedBrand: null,
        brandDomainMismatch: null,
        source: "body",
        interaction: "navigation",
      }],
      authentication: { providerTrust: "trusted", spf: "fail", dkim: "fail", dmarc: "fail", arc: "none" },
    });
    const result = scanMessage(polished, emptyDeps);
    expect(codesFromScan(polished)).toContain("CREDENTIAL_PHISH_INTENT");
    expect(result.scored.verdict).toBe("high_risk");
  });

  it("detects multilingual credential and payment-diversion pressure with legitimate-language controls", () => {
    const urduCredential = envelope({
      subject: "اکاؤنٹ سیکیورٹی",
      textPreview: "اپنا پاس ورڈ فوری درج کریں ورنہ اکاؤنٹ بند ہو جائے گا۔",
      authentication: { providerTrust: "trusted", spf: "fail", dkim: "fail", dmarc: "fail", arc: "none" },
    });
    expect(codesFromIntent(urduCredential)).toContain("MULTILINGUAL_CREDENTIAL_PHISH_INTENT");

    const spanishDiversion = envelope({
      subject: "Solicitud urgente",
      textPreview: "Necesito una tarjeta de regalo urgente. Mantén esto secreto y envía el código hoy.",
      authentication: { providerTrust: "trusted", spf: "fail", dkim: "fail", dmarc: "fail", arc: "none" },
    });
    expect(codesFromIntent(spanishDiversion)).toContain("MULTILINGUAL_PAYMENT_DIVERSION_INTENT");

    const legitimate = envelope({
      subject: "Actualización de cuenta",
      textPreview: "Su resumen mensual está disponible en la aplicación oficial. No se requiere ninguna acción inmediata.",
    });
    expect(codesFromIntent(legitimate).filter((code) => code.startsWith("MULTILINGUAL_"))).toEqual([]);
  });

  it("treats a known-contact authentication/reply-route takeover as high risk despite prior history", () => {
    const takeover = envelope({
      from: { displayName: "Known Vendor", address: "billing@known-vendor.example", domain: "known-vendor.example" },
      replyTo: { displayName: "Known Vendor", address: "payments@new-route.example", domain: "new-route.example" },
      subject: "Updated payment details",
      textPreview: "Please update the bank transfer details for today's invoice.",
      authentication: { providerTrust: "trusted", spf: "fail", dkim: "fail", dmarc: "fail", arc: "none" },
      threadContext: {
        isFirstContact: false,
        threadContinuityBroken: false,
        replyToChangedMidThread: true,
        relationshipPriorMessages: 14,
        relationshipPriorAuthenticatedMessages: 14,
        relationshipPriorSafeMessages: 14,
        relationshipPriorSuspiciousMessages: 0,
        hasEstablishedSenderHistory: true,
        relationshipAuthenticationDowngrade: true,
        replyToChangedFromRelationshipHistory: true,
      },
    });
    const result = scanMessage(takeover, emptyDeps);
    const codes = result.scored.evidence.map((item) => item.code);
    expect(codes).toContain("RELATIONSHIP_AUTH_DOWNGRADE");
    expect(codes).toContain("RELATIONSHIP_REPLY_TO_CHANGE");
    expect(result.scored.verdict).toBe("high_risk");
  });

  it("keeps a full-context BEC payment diversion high risk even when its only link looks ordinary", () => {
    const bec = envelope({
      from: { displayName: "Chief Executive Officer", address: "ceo.office@company-corp-inc.example", domain: "company-corp-inc.example" },
      subject: "Quick request",
      textPreview: "Are you available right now? I urgently need you to process a wire transfer to a new vendor. Keep this confidential and do not discuss it with anyone else.",
      links: [{
        visibleText: "Vendor request",
        rawUrl: "https://portal.company-corp-inc.example/request/42",
        normalizedUrl: "https://portal.company-corp-inc.example/request/42",
        claimedBrand: null,
        brandDomainMismatch: null,
        source: "body",
        interaction: "navigation",
      }],
      authentication: { providerTrust: "trusted", spf: "fail", dkim: "fail", dmarc: "fail", arc: "none" },
    });
    const result = scanMessage(bec, emptyDeps);
    expect(result.scored.evidence.map((item) => item.code)).toContain("BEC_INTENT");
    expect(result.scored.verdict).toBe("high_risk");
  });

  it("analyzes image-only phishing through local visual text and never calls unavailable visual coverage Safe", async () => {
    const image = onePixelPng();
    const localVisualText: VisualTextExtractor = {
      async extract() {
        return {
          text: "Unusual sign-in activity detected. Verify your account within 24 hours and enter your password and one-time passcode.",
          complete: true,
        };
      },
    };
    const analyzed = await evaluateSubmittedImage({
      content: image,
      mimeType: "image/png",
      name: "security-notice.png",
    }, {}, { visualTextExtractor: localVisualText });
    expect(analyzed.evidence.map((item) => item.code)).toContain("CREDENTIAL_PHISH_INTENT");
    expect(analyzed.verdict).not.toBe("safe");

    const unavailable = await evaluateSubmittedImage({
      content: image,
      mimeType: "image/png",
      name: "uninspected-notice.png",
    });
    expect(unavailable.verdict).not.toBe("safe");
    expect(unavailable.explanation.limitations.join(" ")).toMatch(/visual-text extractor|not considered fully inspected/i);
  });
});
