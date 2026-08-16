import { describe, expect, it } from "vitest";
import { extractStructuralScamFacts } from "../../server/src/engine/structuralScamEvidence.js";

function facts(text: string) {
  return extractStructuralScamFacts({ subject: "", text, htmlText: null, displayName: null, links: [] });
}

describe("structural scam fact topology boundaries", () => {
  it("does not combine an OTP mention with an unrelated later request to send feedback", () => {
    const result = facts("Your OTP was used to sign in successfully. Send feedback about the redesigned dashboard when convenient.");
    expect(result.requestedActions).not.toContain("send_otp");
  });

  it("does not combine a password notification with an unrelated request to send feedback", () => {
    const result = facts("Your password was changed successfully. Send feedback about the account settings page when convenient.");
    expect(result.requestedActions).not.toContain("send_recovery_secret");
  });

  it("does not combine ordinary gift-card commerce copy with an unrelated shipping request", () => {
    const result = facts("We sell physical and digital gift cards. Send your shipping address for physical orders. Digital codes remain available only inside your account.");
    expect(result.requestedActions).not.toContain("send_gift_card_code");
  });

  it("does not classify ordinary PayPal references as a high-friction cash-app instrument", () => {
    const result = facts("Your PayPal receipt is available. No payment action is required and buyer protection remains unchanged.");
    expect(result.paymentInstruments).not.toContain("cash_app");
  });

  it("still recognizes an explicit PayPal Friends and Family transfer instruction as high-friction", () => {
    const result = facts("Send the payment using PayPal Friends and Family within 30 minutes.");
    expect(result.paymentInstruments).toContain("cash_app");
    expect(result.requestedActions).toContain("pay");
    expect(result.pressure).toContain("deadline");
  });
});
