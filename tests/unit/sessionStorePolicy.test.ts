import { describe, expect, it } from "vitest";
import { ReviewActionConflictError, SessionStore } from "../../server/src/api/sessionStore.js";
import {
  InMemoryPolicyRepository,
  type PersonalPolicyRepository,
} from "../../server/src/api/policyPersistence.js";
import type { ScanActionContext } from "../../server/src/workflows/scanWorkflows.js";

function reviewContext(overrides: Partial<ScanActionContext> = {}): ScanActionContext {
  return {
    providerNativeId: "uid-1",
    messageId: "message-1",
    exceptionKey: `message:${"a".repeat(64)}`,
    senderAddress: "sender@example.com",
    normalizedFolder: "inbox",
    links: [],
    unsubscribe: { available: false, method: "none", target: null, source: "none" },
    communityReport: {
      campaignFingerprint: "d".repeat(64),
      indicators: [
        { type: "campaign", value: "d".repeat(64) },
        { type: "sender", value: "sender@example.com" },
      ],
      evidenceCodes: ["TEST_EVIDENCE"],
      evidenceScore: 6,
      verdict: "high_risk",
    },
    ...overrides,
  };
}

describe("account-scoped personal policy", () => {
  it("atomically rejects a duplicate review operation while allowing an explicit retry after pre-commit failure", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const session = store.create("gmail", "fixture", { provider: "gmail", mode: "fixture" });
    const registered = store.registerReviewAction(session, reviewContext());
    const claimed = store.claimReviewAction(session, registered.token, "trash");
    expect(() => store.claimReviewAction(session, registered.token, "trash")).toThrow(ReviewActionConflictError);
    store.releaseReviewAction(claimed, "trash");
    expect(store.claimReviewAction(session, registered.token, "trash")).toBe(claimed);
  });

  it("keeps selected-account and last-scan presentation bounded to process memory", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const session = store.create("gmail", "fixture", { provider: "gmail", mode: "fixture" });
    const counters = { examined: 0, safe: 0, review: 0, highRisk: 0, confirmedThreat: 0, unknown: 0, skipped: 0, malformed: 0 };
    store.beginWorkspaceScan(session, "scan-1", "quick", counters);
    store.rememberWorkspaceProgress(session, {
      counters: { ...counters, examined: 600 },
      suspiciousCards: Array.from({ length: 250 }, (_, index) => ({ index })),
      diagnosticSummaries: Array.from({ length: 600 }, (_, index) => ({ index })),
    });
    store.finishWorkspaceScan(session, "completed");
    const workspace = store.workspaceSnapshot();
    expect(workspace.selectedAccountId).toBe(session.id);
    expect(workspace.presentation?.suspiciousCards).toHaveLength(200);
    expect(workspace.presentation?.diagnosticSummaries).toHaveLength(500);
    expect(workspace.presentation?.status).toBe("completed");
  });

  it("does not leak rules between different accounts", () => {
    const repository = new InMemoryPolicyRepository();
    const store = new SessionStore(repository);
    const first = store.create("icloud", "first", {
      provider: "icloud", mode: "live", credentials: { user: "first@icloud.com", appPassword: "test" },
    });
    const second = store.create("icloud", "second", {
      provider: "icloud", mode: "live", credentials: { user: "second@icloud.com", appPassword: "test" },
    });

    first.personalPolicy.blockSender("blocked@example.com");
    first.personalPolicy.blockDomain("example.net");
    first.personalPolicy.trustSender("trusted@example.org");
    first.personalPolicy.approveException(`message:${"b".repeat(64)}`);
    first.personalPolicy.rememberUnsubscribed("campaign-key");
    first.personalPolicy.reportCampaign("e".repeat(64));
    store.persistPersonalPolicy(first);

    expect(second.personalPolicy.isBlockedSender("blocked@example.com")).toBe(false);
    expect(second.personalPolicy.isBlockedDomain("example.net")).toBe(false);
    expect(second.personalPolicy.isTrustedSender("trusted@example.org")).toBe(false);
    expect(second.personalPolicy.isApprovedException(`message:${"b".repeat(64)}`)).toBe(false);
    expect(second.personalPolicy.isUnsubscribedAction("campaign-key")).toBe(false);
    expect(second.personalPolicy.isReportedCampaign("e".repeat(64))).toBe(false);
  });

  it("shares one live policy object between simultaneous sessions for the same mailbox", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const first = store.create("icloud", "first tab", {
      provider: "icloud", mode: "live", credentials: { user: "same@icloud.com", appPassword: "first" },
    });
    const second = store.create("icloud", "second tab", {
      provider: "icloud", mode: "live", credentials: { user: "SAME@ICLOUD.COM", appPassword: "second" },
    });
    first.personalPolicy.trustSender("trusted@example.com");
    expect(second.personalPolicy).toBe(first.personalPolicy);
    expect(second.personalPolicy.isTrustedSender("trusted@example.com")).toBe(true);
  });

  it("restores blocks, trust, exact approvals, unsubscribe history, and reported campaigns after restart", async () => {
    const repository = new InMemoryPolicyRepository();
    const config = {
      provider: "icloud" as const,
      mode: "live" as const,
      credentials: { user: "Usama@iCloud.com", appPassword: "first-password" },
    };
    const firstProcess = new SessionStore(repository);
    const original = firstProcess.create("icloud", "original", config);
    original.personalPolicy.blockSender("blocked@example.com");
    original.personalPolicy.trustSender("trusted@example.com");
    original.personalPolicy.approveException(`message:${"c".repeat(64)}`);
    original.personalPolicy.rememberUnsubscribed("campaign-key");
    original.personalPolicy.reportCampaign("e".repeat(64));
    firstProcess.persistPersonalPolicy(original);
    await firstProcess.remove(original.id);

    const restartedProcess = new SessionStore(repository);
    const reconnected = restartedProcess.create("icloud", "reconnected", {
      ...config,
      credentials: { user: "usama@icloud.com", appPassword: "new-password" },
    });
    expect(reconnected.personalPolicy.isBlockedSender("blocked@example.com")).toBe(true);
    expect(reconnected.personalPolicy.isTrustedSender("trusted@example.com")).toBe(true);
    expect(reconnected.personalPolicy.isApprovedException(`message:${"c".repeat(64)}`)).toBe(true);
    expect(reconnected.personalPolicy.isUnsubscribedAction("campaign-key")).toBe(true);
    expect(reconnected.personalPolicy.isReportedCampaign("e".repeat(64))).toBe(true);
  });

  it("rolls back a mutation when encrypted persistence fails", () => {
    const failingRepository: PersonalPolicyRepository = {
      persistent: true,
      load: () => ({
        blockedSenders: ["original@example.com"],
        blockedDomains: [],
        trustedSenders: [],
        approvedExceptions: [],
        unsubscribedActions: [],
        reportedCampaigns: [],
      }),
      save: () => { throw new Error("disk full"); },
    };
    const store = new SessionStore(failingRepository);
    const session = store.create("icloud", "fixture", { provider: "icloud", mode: "fixture" });

    expect(() => store.mutateAndPersistPersonalPolicy(
      session,
      (policy) => policy.trustSender("should-not-remain@example.com"),
    )).toThrow("disk full");
    expect(session.personalPolicy.isBlockedSender("original@example.com")).toBe(true);
    expect(session.personalPolicy.isTrustedSender("should-not-remain@example.com")).toBe(false);
  });
});

describe("opaque message review actions", () => {
  it("issues account-scoped tokens without exposing community indicators in the token", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const first = store.create("gmail", "first", { provider: "gmail", mode: "fixture" });
    const second = store.create("outlook", "second", { provider: "outlook", mode: "fixture" });
    const context = reviewContext();
    const registered = store.registerReviewAction(first, context);

    expect(registered.token).not.toContain(context.exceptionKey);
    expect(registered.token).not.toContain(context.communityReport.campaignFingerprint);
    expect(registered.canMoveToSpam).toBe(true);
    expect(registered.canReportSpam).toBe(true);
    expect(registered.communityReported).toBe(false);
    expect(store.resolveReviewAction(first, registered.token)).toMatchObject({
      exceptionKey: context.exceptionKey,
      senderAddress: context.senderAddress,
      providerNativeId: context.providerNativeId,
      normalizedFolder: "inbox",
      communityReport: context.communityReport,
    });
    expect(() => store.resolveReviewAction(second, registered.token)).toThrow("unknown or expired");
  });

  it("keeps visible review actions valid across scan Stop/Resume housekeeping", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const session = store.create("gmail", "mailbox", { provider: "gmail", mode: "fixture" });
    const action = store.registerReviewAction(session, reviewContext());

    store.clearScanActions(session);

    expect(store.resolveReviewAction(session, action.token)).toMatchObject({
      providerNativeId: "uid-1",
      senderAddress: "sender@example.com",
    });
  });

  it("does not offer provider Spam/Junk movement for a message already there", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const session = store.create("imap", "mailbox", { provider: "imap", mode: "fixture" });
    expect(store.registerReviewAction(session, reviewContext({ normalizedFolder: "spam" })).canMoveToSpam).toBe(false);
  });

  it("reports existing Safe, trust, and community decisions", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const session = store.create("yahoo", "mailbox", { provider: "yahoo", mode: "fixture" });
    const context = reviewContext();
    session.personalPolicy.approveException(context.exceptionKey);
    session.personalPolicy.trustSender(context.senderAddress!);
    session.personalPolicy.reportCampaign(context.communityReport.campaignFingerprint);

    expect(store.registerReviewAction(session, context)).toMatchObject({
      alreadyApproved: true,
      senderTrusted: true,
      canMoveToSpam: true,
      communityReported: true,
    });
  });
});

describe("account-scoped unsubscribe actions", () => {
  it("issues opaque unique tokens while grouping duplicate campaign targets", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const session = store.create("icloud", "mailbox", {
      provider: "icloud", mode: "live", credentials: { user: "same@icloud.com", appPassword: "test" },
    });

    const first = store.registerUnsubscribeAction(session, "one_click_post", "https://example.test/unsub?id=1", "uid-1");
    const second = store.registerUnsubscribeAction(session, "one_click_post", "https://example.test/unsub?id=1", "uid-2");

    expect(first.token).not.toBe(second.token);
    expect(first.actionKey).toBe(second.actionKey);
    expect(first.token).not.toContain("example.test");
    expect(store.resolveUnsubscribeAction(session, first.token)).toMatchObject({
      method: "one_click_post",
      target: "https://example.test/unsub?id=1",
      providerNativeId: "uid-1",
      actionKey: first.actionKey,
    });
  });

  it("does not merge manual links and one-click posts that share a URL", () => {
    const store = new SessionStore(new InMemoryPolicyRepository());
    const session = store.create("imap", "mailbox", { provider: "imap", mode: "fixture" });
    const automatic = store.registerUnsubscribeAction(session, "one_click_post", "https://example.test/unsub", "uid-1");
    const manual = store.registerUnsubscribeAction(session, "link_only", "https://example.test/unsub", "uid-2");
    expect(automatic.actionKey).not.toBe(manual.actionKey);
  });

  it("persists completed unsubscribe status while scan transitions retain bounded action capabilities", () => {
    const repository = new InMemoryPolicyRepository();
    const store = new SessionStore(repository);
    const session = store.create("yahoo", "mailbox", { provider: "yahoo", mode: "fixture" });
    const action = store.registerUnsubscribeAction(session, "one_click_post", "https://example.test/unsub", "uid-1");
    store.markUnsubscribed(session, action.actionKey);
    store.clearScanActions(session);

    expect(store.resolveUnsubscribeAction(session, action.token)).toMatchObject({ actionKey: action.actionKey });
    expect(session.personalPolicy.isUnsubscribedAction(action.actionKey)).toBe(true);
    expect(store.registerUnsubscribeAction(session, "one_click_post", "https://example.test/unsub", "uid-2").alreadyUnsubscribed).toBe(true);
  });
});