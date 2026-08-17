import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SessionStore } from "../../server/src/api/sessionStore.js";
import { InMemoryPolicyRepository } from "../../server/src/api/policyPersistence.js";
import type { ScanActionContext } from "../../server/src/workflows/scanWorkflows.js";

const webRoot = join(import.meta.dirname, "../../web");

function reviewContext(): ScanActionContext {
  return {
    providerNativeId: "uid-ema8",
    messageId: "message-ema8",
    exceptionKey: `message:${"a".repeat(64)}`,
    senderAddress: "sender@example.com",
    normalizedFolder: "inbox",
    links: [],
    unsubscribe: { available: false, method: "none", target: null, source: "none" },
    communityReport: {
      campaignFingerprint: "d".repeat(64),
      indicators: [{ type: "campaign", value: "d".repeat(64) }],
      evidenceCodes: ["TEST_EVIDENCE"],
      evidenceScore: 6,
      verdict: "high_risk",
    },
  };
}

function workspaceReviewAction(store: SessionStore): Record<string, unknown> {
  const card = store.workspaceSnapshot().presentation?.suspiciousCards[0] as { reviewAction?: Record<string, unknown> } | undefined;
  return card?.reviewAction ?? {};
}

describe("EMA-8 campaign decision availability", () => {
  it("restored workspace cards stop offering Report Scam once the mutually-exclusive campaign decision is claimed", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const session = store.create("gmail", "fixture", { provider: "gmail", mode: "fixture" });
    const action = store.registerReviewAction(session, reviewContext());
    const counters = { examined: 1, safe: 0, review: 1, highRisk: 0, confirmedThreat: 0, unknown: 0, skipped: 0, malformed: 0 };

    store.beginWorkspaceScan(session, "scan-ema8", "quick", counters);
    store.rememberWorkspaceProgress(session, {
      suspiciousCards: [{ reviewAction: action }],
    });

    expect(workspaceReviewAction(store).reportScamAvailable).toBe(true);

    const claimed = store.claimReviewAction(session, action.token, "report_scam");
    expect(workspaceReviewAction(store).reportScamAvailable).toBe(false);

    store.releaseReviewAction(claimed, "report_scam");
    expect(workspaceReviewAction(store).reportScamAvailable).toBe(true);
  });

  it("renders Report Scam from server availability rather than scan-time campaign state alone", () => {
    const source = readFileSync(join(webRoot, "review-actions.js"), "utf8");
    expect(source).toContain("action.reportScamAvailable === false");
    expect(source).toContain("Campaign decision already saved");
  });

  it("keeps Report Scam ownership in review-actions while positive learning publishes pending, saved, and rollback state", () => {
    const learning = readFileSync(join(webRoot, "protection-learning.js"), "utf8");
    const review = readFileSync(join(webRoot, "review-actions.js"), "utf8");

    expect(learning).toContain("email-shield-campaign-decision-state");
    expect(learning).toContain("publishCampaignDecisionState(token, 'pending')");
    expect(learning).toContain("publishCampaignDecisionState(token, 'saved')");
    expect(learning).toContain("publishCampaignDecisionState(token, 'available')");
    expect(learning).not.toContain("[data-action=\"report-scam\"]");

    expect(review).toContain("email-shield-campaign-decision-state");
    expect(review).toContain("setReportScamAvailability(token, false");
    expect(review).toContain("setReportScamAvailability(token, true");
    expect(review).toContain("Campaign decision already saved");
  });
});
