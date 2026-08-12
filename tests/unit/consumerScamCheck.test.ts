import { describe, expect, it } from "vitest";
import {
  ConsumerScamCheckError,
  evaluateConsumerScamCheck,
} from "../../server/src/consumer/scamCheck.js";

describe("consumer Scam Check", () => {
  it("uses the existing deterministic engine for full-context callback and link risk", () => {
    const result = evaluateConsumerScamCheck({
      schemaVersion: 1,
      kind: "message",
      subject: "Your subscription was renewed",
      text: "Your subscription was charged. If you did not authorize this, call us now at (555) 123-4567. Review details at http://192.0.2.44/login",
    });

    expect(result.verdict).toBe("high_risk");
    expect(result.action).toBe("allow_one_click_block");
    expect(result.evidence.some((item) => item.code === "CALLBACK_SCAM_INTENT")).toBe(true);
    expect(result.evidence.some((item) => item.code === "RAW_IP_HOST")).toBe(true);
    expect(result.explanation.scamCategory).toBe("callback_refund");
    expect(result.explanation.evidenceStrength).toBe("strong");
    expect(result.explanation.safeNextActions.join(" ")).toMatch(/independently/i);
  });

  it("detects unsafe URL schemes without navigating to them", () => {
    const result = evaluateConsumerScamCheck({
      schemaVersion: 1,
      kind: "url",
      url: "javascript:alert(document.domain)",
    });

    expect(result.evidence.some((item) => item.code === "UNSAFE_LINK_SCHEME")).toBe(true);
    expect(["review", "high_risk"]).toContain(result.verdict);
  });

  it("does not invent trusted mailbox authentication for submitted content", () => {
    const result = evaluateConsumerScamCheck({
      schemaVersion: 1,
      kind: "message",
      text: "Dinner is at seven. See you there.",
      sender: { displayName: "Alex", address: "alex@example.com" },
    });

    const transport = result.layerResults.find((layer) => layer.layer === "transport_auth");
    expect(transport?.incomplete).toBe(true);
    expect(result.explanation.limitations.join(" ")).toMatch(/does not have trusted mailbox transport\/authentication provenance/i);
    expect(result.confirmedByRule).toBe(false);
  });

  it("keeps personal policy and signed intelligence outside the untrusted request contract", () => {
    expect(() => evaluateConsumerScamCheck({
      schemaVersion: 1,
      kind: "message",
      text: "hello",
      personalPolicy: {
        blockedSenders: [],
        blockedDomains: [],
        trustedSenders: [],
        approvedExceptions: [],
        unsubscribedActions: [],
        reportedCampaigns: [],
      },
    })).toThrowError(ConsumerScamCheckError);
  });

  it("rejects empty message checks rather than returning a misleading safe result", () => {
    expect(() => evaluateConsumerScamCheck({
      schemaVersion: 1,
      kind: "message",
      text: "   ",
    })).toThrowError(ConsumerScamCheckError);
  });

  it("bounds submitted text before engine execution", () => {
    expect(() => evaluateConsumerScamCheck({
      schemaVersion: 1,
      kind: "message",
      text: "a".repeat(512 * 1024 + 1),
    })).toThrowError(ConsumerScamCheckError);
  });
});
