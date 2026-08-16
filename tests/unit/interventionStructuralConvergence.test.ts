import { describe, expect, it } from "vitest";
import { assessScamIntervention } from "../../server/src/consumer/intervention.js";

describe("payment/callback intervention structural convergence", () => {
  it("does not treat a passive remote-tool mention as a remote-access request", () => {
    const result = assessScamIntervention("Our help article compares AnyDesk and TeamViewer. No installation, remote control, payment, or account action is requested.");

    expect(result.signals.some((signal) => signal.code === "REMOTE_ACCESS_REQUEST")).toBe(false);
    expect(result.officialVerificationRequired).toBe(false);
  });

  it("does not label passive PayPal or gift-card commerce copy as a requested payment", () => {
    const result = assessScamIntervention("Your PayPal receipt is available. Our store also supports gift cards. No payment, transfer, card code, or response is requested.");

    expect(result.requestedPaymentMethods).toEqual([]);
    expect(result.signals.some((signal) => signal.severity === "critical")).toBe(false);
  });

  it("uses shared structural facts for gift-card code exfiltration", () => {
    const result = assessScamIntervention("Your manager needs $500 in Apple gift cards today. Send clear photos of the codes. Do not call; keep this between us.");

    expect(result.signals).toContainEqual(expect.objectContaining({
      code: "GIFT_CARD_CODE_EXFILTRATION",
      severity: "critical",
    }));
    expect(result.requestedPaymentMethods).toContain("gift card");
  });

  it("uses shared structural facts for OTP exfiltration", () => {
    const result = assessScamIntervention("Security department here. Read back the one-time verification code so we can stop the account lock.");

    expect(result.signals).toContainEqual(expect.objectContaining({
      code: "ACCOUNT_ACCESS_SECRET_REQUEST",
      severity: "critical",
    }));
  });

  it("requires a remote-access request plus financial/account context for a critical remote signal", () => {
    const result = assessScamIntervention("Bank fraud team: install AnyDesk so we can secure the account and process the refund.");

    expect(result.signals).toContainEqual(expect.objectContaining({
      code: "REMOTE_ACCESS_REQUEST",
      severity: "critical",
    }));
  });

  it("uses shared payment pressure for an irreversible crypto deadline", () => {
    const result = assessScamIntervention("Send 800 USDT to the wallet within 30 minutes to release the payment review. This transfer cannot be reversed.");

    expect(result.signals).toContainEqual(expect.objectContaining({
      code: "URGENT_IRREVERSIBLE_PAYMENT_REQUEST",
      severity: "critical",
    }));
    expect(result.requestedPaymentMethods).toContain("cryptocurrency");
  });
});
