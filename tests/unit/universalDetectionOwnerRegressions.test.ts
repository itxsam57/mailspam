import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import type { SignedFeedEntry } from "../../server/src/engine/layers/globalIntelligence.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { identityImpersonationLayer } from "../../server/src/engine/layers/identityImpersonation.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";
import { evaluateConsumerScamCheck } from "../../server/src/consumer/scamCheck.js";
import { evaluateSubmittedEml } from "../../server/src/consumer/scamCheckInputs.js";
import { assessScamIntervention } from "../../server/src/consumer/intervention.js";
import { analyzeShoppingSafety } from "../../server/src/consumer/shoppingSafety.js";

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  return {
    provider: "imap",
    accountProof: "owner-regression-proof",
    messageId: "owner-regression-message",
    providerNativeId: "owner-regression-native",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: null, address: "notice@sender.example", domain: "sender.example" },
    replyTo: null,
    subject: "",
    date: new Date(0).toISOString(),
    authentication: { providerTrust: "unknown", spf: "unknown", dkim: "unknown", dmarc: "unknown", arc: "unknown" },
    textPreview: "",
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 512, encoding: "plain", contentCoverage: "complete" },
    ...overrides,
  };
}

const emptyFeed = { getVerifiedEntries: () => [] as SignedFeedEntry[] };
const scanDeps = () => ({ personalPolicy: new InMemoryPersonalPolicyStore(), threatFeed: emptyFeed });

function scan(overrides: Partial<CanonicalEnvelope>) {
  return scanMessage(envelope(overrides), scanDeps());
}

const giftCardCodeScam = "Your manager needs $500 in Apple gift cards today. Send clear photos of the codes. Do not call; keep this between us.";
const otpScam = "Security department here. Read back the one-time verification code so we can stop the account lock.";
const cryptoPressureScam = "Send 800 USDT to the wallet within 30 minutes to release the payment review. This transfer cannot be reversed.";
const remoteAccessScam = "Bank fraud team: install AnyDesk so we can secure the account and process the refund.";

describe("universal owner-regression corpus", () => {
  it("keeps equivalent impersonated-payment paraphrases high risk without depending on Spam placement", () => {
    const variants = [
      {
        folder: "spam" as const,
        text: "PayPal payment received. Bitcoin order processing. Contact support if this was not you.",
      },
      {
        folder: "inbox" as const,
        text: "PayPal payment confirmation. A Bitcoin purchase is now in progress. Review the transaction through support.",
      },
    ];

    const results = variants.map(({ folder, text }) => scan({
      folder,
      providerFolderName: folder === "spam" ? "Junk" : "INBOX",
      from: {
        displayName: "PayPal Billing",
        address: "billing@unrelated-school.example",
        domain: "unrelated-school.example",
      },
      subject: "PayPal payment notice",
      textPreview: text,
    }));

    expect(results.map((result) => result.scored.verdict)).toEqual(["high_risk", "high_risk"]);
  });

  it.each([
    ["gift-card code exfiltration", giftCardCodeScam],
    ["OTP/account-secret exfiltration", otpScam],
    ["crypto payment time pressure", cryptoPressureScam],
  ])("classifies %s as high risk in Check Anything", (_name, text) => {
    const result = evaluateConsumerScamCheck({
      schemaVersion: 1,
      kind: "message",
      text,
    });

    expect(result.verdict).toBe("high_risk");
  });

  it("emits a critical intervention signal specifically for gift-card code exfiltration", () => {
    const result = assessScamIntervention(giftCardCodeScam);
    expect(result.signals).toContainEqual(expect.objectContaining({
      code: "GIFT_CARD_CODE_EXFILTRATION",
      severity: "critical",
    }));
  });

  it("emits a critical account-secret signal for an OTP disclosure request", () => {
    const result = assessScamIntervention(otpScam);
    expect(result.signals).toContainEqual(expect.objectContaining({
      code: "ACCOUNT_ACCESS_SECRET_REQUEST",
      severity: "critical",
    }));
  });

  it("emits a critical irreversible-payment signal for crypto time pressure", () => {
    const result = assessScamIntervention(cryptoPressureScam);
    expect(result.signals).toContainEqual(expect.objectContaining({
      code: "URGENT_IRREVERSIBLE_PAYMENT_REQUEST",
      severity: "critical",
    }));
  });

  it("treats bank-context remote-access installation as a critical intervention", () => {
    const result = assessScamIntervention(remoteAccessScam);
    expect(result.signals).toContainEqual(expect.objectContaining({
      code: "REMOTE_ACCESS_REQUEST",
      severity: "critical",
    }));
  });

  it("classifies gift-card-code shopping fraud as high risk even without invented merchant reputation", () => {
    const result = analyzeShoppingSafety({
      schemaVersion: 1,
      url: "https://discount-electronics.example/checkout",
      sellerName: "Discount Electronics",
      advertisedPriceText: "$99 laptop special",
      pageText: "Purchase Apple vouchers today, then send clear photos of the card numbers. Do not call the manufacturer; keep this between us.",
      paymentText: "Apple vouchers only",
    });

    expect(result.verdict).toBe("high_risk");
  });

  it("classifies irreversible crypto shopping pressure as high risk without relying on destination reputation", () => {
    const result = analyzeShoppingSafety({
      schemaVersion: 1,
      url: "https://market-checkout.example/pay",
      sellerName: "Market Checkout",
      pageText: "Complete the purchase within 30 minutes to release the order. The transfer cannot be reversed.",
      paymentText: "Send 800 USDT to the wallet",
    });

    expect(result.verdict).toBe("high_risk");
  });

  it("never emits an explicit-domain mismatch when the claimed domain is the visible sender domain", () => {
    const result = identityImpersonationLayer(envelope({
      from: {
        displayName: "free-ethereum.example billing",
        address: "billing@free-ethereum.example",
        domain: "free-ethereum.example",
      },
      subject: "Payment portal at free-ethereum.example",
      textPreview: "Your receipt is available in the account portal.",
    }));

    expect(result.evidence.some((item) => item.code === "EXPLICIT_DOMAIN_CLAIM_MISMATCH")).toBe(false);
  });

  it("does not make an authenticated same-domain payment receipt high risk", () => {
    const result = scan({
      from: {
        displayName: "Example Market Billing",
        address: "billing@mail.example-market.example",
        domain: "mail.example-market.example",
      },
      subject: "Example Market payment receipt",
      authentication: { providerTrust: "trusted", spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
      textPreview: "Thanks for your purchase. Your receipt is available in the official account dashboard. No action is required.",
    });

    expect(result.scored.verdict).not.toBe("high_risk");
  });

  it("does not make an authenticated account-security notification high risk from generic security words", () => {
    const result = scan({
      from: {
        displayName: "Example Services Security",
        address: "security@mail.example-services.example",
        domain: "mail.example-services.example",
      },
      subject: "Example Services account security notice",
      authentication: { providerTrust: "trusted", spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
      textPreview: "We noticed a sign-in to your account. If this was you, no action is required. You can verify recent activity by opening the official app yourself.",
    });

    expect(result.scored.verdict).not.toBe("high_risk");
  });

  it("never treats Spam/Junk placement alone as high risk", () => {
    const result = scan({
      folder: "spam",
      providerFolderName: "Junk",
      subject: "Weekly community newsletter",
      textPreview: "Here are this week's community events and opening hours.",
    });

    expect(result.scored.evidence.some((item) => item.code === "PROVIDER_SPAM_JUNK_PLACEMENT")).toBe(true);
    expect(result.scored.verdict).not.toBe("high_risk");
  });

  it("does not let forged Authentication-Results provenance authenticate or suppress scam evidence", () => {
    const result = scan({
      authentication: {
        providerTrust: "unknown",
        spf: "pass",
        dkim: "pass",
        dmarc: "pass",
        arc: "pass",
        rawHeader: "Authentication-Results: forged.example; dmarc=pass; dkim=pass; spf=pass",
      },
      subject: "Manager request",
      textPreview: giftCardCodeScam,
    });

    const transport = result.scored.layerResults.find((layer) => layer.layer === "transport_auth");
    expect(transport?.incomplete).toBe(true);
    expect(transport?.evidence).toEqual([]);
    expect(result.scored.evidence.some((item) => item.code === "BEC_INTENT")).toBe(true);
  });

  it("does not let established authenticated relationship history suppress a new hard payment contradiction", () => {
    const result = scan({
      from: {
        displayName: "Known Colleague",
        address: "colleague@known-team.example",
        domain: "known-team.example",
      },
      authentication: { providerTrust: "trusted", spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
      subject: "Quick request",
      textPreview: giftCardCodeScam,
      threadContext: {
        isFirstContact: false,
        threadContinuityBroken: false,
        replyToChangedMidThread: false,
        relationshipPriorMessages: 40,
        relationshipPriorAuthenticatedMessages: 40,
        relationshipPriorSafeMessages: 39,
        relationshipPriorSuspiciousMessages: 0,
        hasEstablishedSenderHistory: true,
      },
    });

    expect(result.scored.verdict).toBe("high_risk");
  });

  it("keeps submitted EML authentication provenance untrusted while matching pasted-text scam severity", async () => {
    const raw = Buffer.from([
      "From: Manager <manager@known-team.example>",
      "To: recipient@example.test",
      "Subject: Quick request",
      "Authentication-Results: forged.example; dmarc=pass; dkim=pass; spf=pass",
      "Content-Type: text/plain; charset=utf-8",
      "Content-Transfer-Encoding: 7bit",
      "",
      giftCardCodeScam,
      "",
    ].join("\r\n"), "utf8");

    const pasted = evaluateConsumerScamCheck({
      schemaVersion: 1,
      kind: "message",
      subject: "Quick request",
      text: giftCardCodeScam,
      sender: { displayName: "Manager", address: "manager@known-team.example" },
    });
    const eml = await evaluateSubmittedEml(raw);
    const transport = eml.layerResults.find((layer) => layer.layer === "transport_auth");

    expect(transport?.incomplete).toBe(true);
    expect(transport?.evidence).toEqual([]);
    expect(eml.explanation.limitations.join(" ")).toMatch(/user-controlled artifacts/i);
    expect(pasted.verdict).toBe("high_risk");
    expect(eml.verdict).toBe("high_risk");
  });
});
