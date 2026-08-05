import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope, LinkInfo } from "../../server/src/canonical/envelope.js";
import { linkStructureLayer } from "../../server/src/engine/layers/linkStructure.js";
import { messageIntentLayer } from "../../server/src/engine/layers/messageIntent.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";

function link(
  visibleText: string,
  destination: string,
  claimedBrand: string | null,
  brandDomainMismatch: boolean | null,
): LinkInfo {
  return {
    visibleText,
    rawUrl: destination,
    normalizedUrl: destination,
    claimedBrand,
    brandDomainMismatch,
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

describe("bounded link-structure evidence", () => {
  it("does not multiply repeated footer mismatches from an official private-relay sender", () => {
    const redotpay = envelope({
      from: {
        displayName: "RedotPay",
        address: "do-not-reply_at_notice_redotpay_com_y242nf6f9z_3759a11a@privaterelay.appleid.com",
        domain: "privaterelay.appleid.com",
      },
      subject: "The RedotPay Food Festival is Happening Now!",
      parseStatus: "partial",
      parseNotes: ["Readable text was bounded to 24576 bytes."],
      diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 40000, encoding: "multipart", contentCoverage: "bounded_sufficient" },
      links: [
        link("RedotPay", "https://tracking.example.net/a", "redotpay", true),
        link("RedotPay", "https://tracking.example.net/b", "redotpay", true),
        link("Instagram", "https://tracking.example.net/c", "instagram", true),
        link("Get it on Google Play", "https://tracking.example.net/d", "google", true),
      ],
    });

    const layer = linkStructureLayer(redotpay);
    const mismatches = layer.evidence.filter((item) => item.code === "LINK_BRAND_MISMATCH");
    expect(mismatches).toHaveLength(1);
    expect(mismatches[0]?.scoreContribution).toBe(1);

    const result = scanMessage(redotpay, deps());
    expect(result.scored.score).toBe(1);
    expect(result.scored.verdict).toBe("safe");
  });

  it("keeps one full-strength mismatch for an unverified sender", () => {
    const spoof = envelope({
      from: { displayName: "RedotPay", address: "promo@evil.example", domain: "evil.example" },
      links: [
        link("RedotPay", "https://evil.example/a", "redotpay", true),
        link("RedotPay", "https://evil.example/b", "redotpay", true),
        link("Instagram", "https://evil.example/c", "instagram", true),
      ],
    });
    const mismatches = linkStructureLayer(spoof).evidence.filter((item) => item.code === "LINK_BRAND_MISMATCH");
    expect(mismatches).toHaveLength(1);
    expect(mismatches[0]?.scoreContribution).toBe(4);
  });

  it("preserves explicit displayed-URL deception", () => {
    const result = linkStructureLayer(envelope({
      links: [link(
        "https://email.mg-d0.substack.com",
        "https://www.surveymonkey.com/r/order-details",
        null,
        null,
      )],
    }));
    expect(result.evidence.some((item) => item.code === "DISPLAYED_VS_ACTUAL_MISMATCH")).toBe(true);
  });
});

describe("crypto yield promotion intent", () => {
  it("moves recurring free-coin and advertised-interest promotions into Review evidence", () => {
    const result = messageIntentLayer(envelope({
      from: { displayName: "News from Free-Ethereum.io", address: "news@free-ethereum.io", domain: "free-ethereum.io" },
      subject: "Earn 6% Interest + Win Free Ethereum Every Hour!",
    }));
    expect(result.evidence).toContainEqual(expect.objectContaining({
      code: "CRYPTO_YIELD_REWARD_PROMOTION",
      scoreContribution: 3,
    }));
  });
});

describe("safe-message audit UI", () => {
  it("loads a separate privacy-reduced Safe list and opens it after completion", () => {
    const root = join(process.cwd(), "..");
    const unsubscribeMonitor = readFileSync(join(root, "web/unsubscribe-monitor.js"), "utf8");
    const safeAudit = readFileSync(join(root, "web/safe-audit.js"), "utf8");

    expect(unsubscribeMonitor).toContain("/safe-audit.js");
    expect(safeAudit).toContain("Safe messages (${sourceRows.length}) — click to review");
    expect(safeAudit).toContain("Safe messages remain outside the warning-card feed");
    expect(safeAudit).toContain("status?.classList.contains('complete')");
    expect(safeAudit).toContain("safeAudit.open = true");
    expect(safeAudit).not.toContain("textPreview");
    expect(safeAudit).not.toContain("htmlSignals");
  });
});
