import { describe, expect, it } from "vitest";
import {
  extractStructuralScamFacts,
  type StructuralScamFacts,
} from "../../server/src/engine/structuralScamEvidence.js";

function facts(text: string, subject = "", displayName: string | null = null): StructuralScamFacts {
  return extractStructuralScamFacts({ subject, text, displayName, htmlText: null, links: [] });
}

describe("provider-neutral structural scam fact extraction", () => {
  it.each([
    "Buy $500 in Apple gift cards and send a picture of the codes to me.",
    "Purchase Apple vouchers today, then reply with clear photos of the card numbers.",
  ])("extracts gift-card value transfer and code exfiltration across wording: %s", (text) => {
    const result = facts(text);

    expect(result.paymentInstruments).toContain("gift_card");
    expect(result.requestedActions).toContain("pay");
    expect(result.requestedActions).toContain("send_gift_card_code");
  });

  it.each([
    "Send a picture of the gift card codes once you buy them.",
    "Reply with the voucher card numbers after purchase.",
  ])("recognizes gift-card code transmission without depending on one exact phrase: %s", (text) => {
    const result = facts(text);

    expect(result.paymentInstruments).toContain("gift_card");
    expect(result.requestedActions).toContain("send_gift_card_code");
  });

  it.each([
    "Read back the one-time verification code so we can stop the lock.",
    "Reply with your OTP to confirm the security review.",
    "Send us the passcode from the sign-in prompt.",
    "Share the one-time code with the security department.",
  ])("maps account-code disclosure requests to send_otp: %s", (text) => {
    const result = facts(text);

    expect(result.requestedActions).toContain("send_otp");
  });

  it("extracts crypto, deadline and irreversibility as separate structural facts", () => {
    const result = facts("Send 800 USDT to the wallet within 30 minutes. This transfer cannot be reversed.");

    expect(result.paymentInstruments).toContain("crypto");
    expect(result.requestedActions).toContain("pay");
    expect(result.pressure).toContain("deadline");
    expect(result.pressure).toContain("irreversible");
  });

  it.each([
    "Install AnyDesk so the bank fraud team can secure the account.",
    "Download TeamViewer and give support remote control for the refund.",
    "Open Quick Assist and allow us to control the device.",
  ])("recognizes an explicit remote-access installation/control request: %s", (text) => {
    expect(facts(text).requestedActions).toContain("install_remote_access");
  });

  it.each([
    "Our help article compares AnyDesk with other remote-support tools.",
    "TeamViewer is listed in the software inventory; no installation is required.",
    "Quick Assist documentation was updated this month.",
  ])("does not turn a passive remote-tool mention into an installation request: %s", (text) => {
    expect(facts(text).requestedActions).not.toContain("install_remote_access");
  });

  it.each([
    "We support gift cards in our store and accept normal card payments.",
    "Your OTP was used to sign in. If this was not you, open the official app yourself.",
    "Never share your verification code with anyone, including support staff.",
  ])("does not manufacture exfiltration actions from benign mentions: %s", (text) => {
    const result = facts(text);

    expect(result.requestedActions).not.toContain("send_gift_card_code");
    expect(result.requestedActions).not.toContain("send_otp");
  });

  it("extracts secrecy and no-independent-contact pressure from a payment-diversion instruction", () => {
    const result = facts("Buy the vouchers today. Keep this between us and do not call me to confirm.");

    expect(result.paymentInstruments).toContain("gift_card");
    expect(result.pressure).toContain("urgent");
    expect(result.pressure).toContain("secrecy");
    expect(result.pressure).toContain("no_independent_contact");
  });

  it("extracts account-loss pressure without treating the account noun itself as dangerous", () => {
    const pressured = facts("Verify the login code now or your account will be suspended.");
    const benign = facts("Your account settings were updated successfully. No action is required.");

    expect(pressured.events).toContain("account_restriction");
    expect(pressured.pressure).toContain("account_loss");
    expect(benign.events).not.toContain("account_restriction");
    expect(benign.pressure).not.toContain("account_loss");
  });

  it("extracts a repeated organization-like transaction claim without a brand database", () => {
    const result = extractStructuralScamFacts({
      displayName: "Cobalt Market Billing",
      subject: "Cobalt Market payment confirmation",
      text: "A purchase is now processing.",
      htmlText: null,
      links: [],
    });

    expect(result.events).toContain("payment");
    expect(result.organizationClaims.join(" ")).toMatch(/cobalt/i);
  });

  it("extracts a leading organization phrase before a transactional subject noun", () => {
    const result = extractStructuralScamFacts({
      displayName: null,
      subject: "Northwind Services payment confirmation",
      text: "A purchase is now processing.",
      htmlText: null,
      links: [],
    });

    expect(result.events).toContain("payment");
    expect(result.organizationClaims.join(" ")).toMatch(/northwind/i);
  });

  it("uses visible link text as structural content but never needs provider metadata", () => {
    const result = extractStructuralScamFacts({
      subject: "",
      text: "Review the request below.",
      htmlText: null,
      displayName: null,
      links: [{
        visibleText: "Pay 800 USDT within 30 minutes",
        rawUrl: "https://checkout.example/pay",
        normalizedUrl: "https://checkout.example/pay",
        source: "body",
      }],
    });

    expect(result.paymentInstruments).toContain("crypto");
    expect(result.requestedActions).toContain("pay");
    expect(result.pressure).toContain("deadline");
  });

  it("deduplicates and deterministically orders facts when the same concept appears repeatedly", () => {
    const first = facts("Pay in bitcoin. Send BTC to the crypto wallet now, now, now. Reply after payment.");
    const second = facts("Pay in bitcoin. Send BTC to the crypto wallet now, now, now. Reply after payment.");

    expect(first).toEqual(second);
    expect(new Set(first.events).size).toBe(first.events.length);
    expect(new Set(first.paymentInstruments).size).toBe(first.paymentInstruments.length);
    expect(new Set(first.requestedActions).size).toBe(first.requestedActions.length);
    expect(new Set(first.pressure).size).toBe(first.pressure.length);
    expect(new Set(first.organizationClaims).size).toBe(first.organizationClaims.length);
  });
});
