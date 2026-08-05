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
    authentication: { spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
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
  it("keeps Safe compact while exposing trust, unsubscribe, and Report Spam through opaque tokens", () => {
    const root = join(process.cwd(), "..");
    const scanMonitor = readFileSync(join(root, "web/scan-monitor.js"), "utf8");
    const unsubscribeMonitor = readFileSync(join(root, "web/unsubscribe-monitor.js"), "utf8");
    const reviewActions = readFileSync(join(root, "web/review-actions.js"), "utf8");
    const safeAudit = readFileSync(join(root, "web/safe-audit.js"), "utf8");

    expect(unsubscribeMonitor).toContain("/safe-audit.js");
    expect(unsubscribeMonitor).toContain("/review-actions.js");
    expect(safeAudit).toContain("Safe messages (${sourceRows.length}) — click to review");
    expect(safeAudit).toContain("Safe messages remain outside the warning-card feed");
    expect(safeAudit).toContain('data-action="trust-sender"');
    expect(safeAudit).toContain('data-action="unsubscribe"');
    expect(safeAudit).toContain('data-action="report-spam"');
    expect(reviewActions).toContain("Mark this message Safe");
    expect(reviewActions).toContain("Report exactly this message as Spam");
    expect(reviewActions).toContain("does not block the sender, delete other mail, or guarantee");
    expect(reviewActions).toContain("body: JSON.stringify({ token })");
    expect(reviewActions).toContain("result.requested !== 1");
    expect(reviewActions).toContain("result.reported !== 1");
    expect(scanMonitor).toContain("data-review-token");
    expect(scanMonitor).toContain("data-can-report-spam");
    expect(scanMonitor).toContain("data-unsubscribe-token");

    for (const browserFile of [scanMonitor, unsubscribeMonitor, reviewActions, safeAudit]) {
      expect(browserFile).not.toContain("listUnsubscribe:");
      expect(browserFile).not.toContain("textPreview");
      expect(browserFile).not.toContain("htmlSignals");
      expect(browserFile).not.toContain("providerNativeId:");
    }
  });
});
