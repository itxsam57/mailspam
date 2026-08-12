import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope, LinkInfo } from "../../server/src/canonical/envelope.js";
import { linkStructureLayer } from "../../server/src/engine/layers/linkStructure.js";
import { messageIntentLayer } from "../../server/src/engine/layers/messageIntent.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";

function link(visibleText: string, destination: string): LinkInfo {
  return {
    visibleText,
    rawUrl: destination,
    normalizedUrl: destination,
    claimedBrand: null,
    brandDomainMismatch: null,
  };
}

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  return {
    provider: "icloud",
    accountProof: "proof",
    messageId: "message-id",
    providerNativeId: "native-id",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Example", address: "news@example.com", domain: "example.com" },
    replyTo: null,
    subject: "Example message",
    date: new Date(0).toISOString(),
    authentication: { providerTrust: "trusted", spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview: "Readable authenticated message content ".repeat(8),
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 1000, encoding: "plain", contentCoverage: "complete" },
    ...overrides,
  };
}

const threatFeed = { getVerifiedEntries: () => [] };
const deps = () => ({ personalPolicy: new InMemoryPersonalPolicyStore(), threatFeed });

describe("organization-neutral link evidence", () => {
  it("does not score ordinary tracked footer labels for a previously unseen relay sender", () => {
    const message = envelope({
      from: {
        displayName: "AcmePay",
        address: "do-not-reply_at_notice_acmepay_example@privaterelay.appleid.com",
        domain: "privaterelay.appleid.com",
      },
      subject: "AcmePay monthly product news",
      parseStatus: "partial",
      parseNotes: ["Readable text was bounded to 24576 bytes."],
      diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 40000, encoding: "multipart", contentCoverage: "bounded_sufficient" },
      links: [
        link("AcmePay", "https://tracking.example.net/a"),
        link("Instagram", "https://tracking.example.net/b"),
        link("Get the mobile app", "https://tracking.example.net/c"),
      ],
    });

    expect(linkStructureLayer(message).evidence).toEqual([]);
    const result = scanMessage(message, deps());
    expect(result.scored.verdict).toBe("safe");
  });

  it("flags a sensitive action that leaves any authenticated sender organization", () => {
    const message = envelope({
      from: { displayName: "Northwind", address: "security@northwind.example", domain: "northwind.example" },
      subject: "Security verification",
      links: [link("Verify your account", "https://credential-check.example.net/login")],
    });
    expect(linkStructureLayer(message).evidence).toContainEqual(expect.objectContaining({
      code: "SENSITIVE_ACTION_CROSS_DOMAIN",
      scoreContribution: 2,
    }));
  });

  it("does not flag a sensitive action that remains inside the sender organization", () => {
    const message = envelope({
      from: { displayName: "Northwind", address: "security@mail.northwind.example", domain: "mail.northwind.example" },
      links: [link("Verify your account", "https://accounts.northwind.example/login")],
    });
    expect(linkStructureLayer(message).evidence.some((item) => item.code === "SENSITIVE_ACTION_CROSS_DOMAIN")).toBe(false);
  });

  it("preserves explicit displayed-URL deception", () => {
    const result = linkStructureLayer(envelope({
      links: [link(
        "https://newsletter.example.org",
        "https://survey-host.example.net/r/order-details",
      )],
    }));
    expect(result.evidence.some((item) => item.code === "DISPLAYED_VS_ACTUAL_MISMATCH")).toBe(true);
  });
});

describe("generic crypto yield promotion intent", () => {
  it("moves recurring free-coin and advertised-interest promotions into Review evidence", () => {
    const result = messageIntentLayer(envelope({
      from: { displayName: "Crypto newsletter", address: "news@unknown-crypto.example", domain: "unknown-crypto.example" },
      subject: "Earn 6% Interest + Win Free Ethereum Every Hour!",
    }));
    expect(result.evidence).toContainEqual(expect.objectContaining({
      code: "CRYPTO_YIELD_REWARD_PROMOTION",
      scoreContribution: 3,
    }));
  });
});

describe("safe-message audit and review UI", () => {
  it("keeps Safe compact while exposing shared Report Scam and separate provider actions through opaque tokens", () => {
const root = join(import.meta.dirname, "../..");
    const scanMonitor = readFileSync(join(root, "web/scan-monitor.js"), "utf8");
    const unsubscribeMonitor = readFileSync(join(root, "web/unsubscribe-monitor.js"), "utf8");
    const reviewActions = readFileSync(join(root, "web/review-actions.js"), "utf8");
    const safeAudit = readFileSync(join(root, "web/safe-audit.js"), "utf8");
    const composition = readFileSync(join(root, "server/src/api/dashboardScripts.ts"), "utf8");

    expect(composition).toContain('"/safe-audit.js"');
    expect(composition).toContain('"/review-actions.js"');
    expect(unsubscribeMonitor).not.toContain("createElement('script')");
    expect(safeAudit).toContain("Safe messages (${sourceRows.length}) — click to review");
    expect(safeAudit).toContain("privacy-reduced community shield");
    expect(safeAudit).toContain('data-action="report-scam"');
    expect(safeAudit).toContain('data-action="move-spam"');
    expect(safeAudit).toContain('data-action="trust-sender"');
    expect(safeAudit).toContain('data-action="unsubscribe"');
    expect(reviewActions).toContain("Report Scam to Email Shield");
    expect(reviewActions).toContain("Move to Spam/Junk");
    expect(reviewActions).toContain("One report cannot globally block a sender");
    expect(reviewActions).toContain("JSON.stringify(isReportScam ? { token, blockSender } : { token })");
    expect(reviewActions).toContain("result.requested !== 1");
    expect(reviewActions).toContain("result.reported !== 1");
    expect(scanMonitor).toContain("data-review-token");
    expect(scanMonitor).toContain("data-can-report-spam");
    expect(scanMonitor).toContain("data-unsubscribe-token");

    for (const browserFile of [scanMonitor, unsubscribeMonitor, reviewActions, safeAudit]) {
      expect(browserFile).not.toContain("listUnsubscribe:");
      expect(browserFile).not.toContain("textPreview");
      expect(browserFile).not.toContain("htmlSignals");
      expect(browserFile).not.toContain("campaignFingerprint");
      expect(browserFile).not.toContain("reporterProof");
      expect(browserFile).not.toContain("action.communityReport");
    }
    expect(reviewActions).not.toContain("providerNativeIds");
    expect(safeAudit).not.toContain("providerNativeIds");
  });
});
