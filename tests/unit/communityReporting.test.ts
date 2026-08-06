import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { buildCommunityReportContext, campaignFingerprint } from "../../server/src/community/fingerprint.js";
import { EncryptedCommunityAggregateStore } from "../../server/src/community/aggregateStore.js";
import { CommunityFeedSigner, verifyCommunityFeed } from "../../server/src/community/signing.js";
import { CommunityNetwork } from "../../server/src/community/network.js";
import type { CommunityReportSubmission } from "../../server/src/community/types.js";
import { InMemoryPersonalPolicyStore, personalRulesLayer } from "../../server/src/engine/layers/personalRules.js";
import { globalIntelligenceLayer } from "../../server/src/engine/layers/globalIntelligence.js";
import type { ScoredMessage } from "../../server/src/engine/verdict.js";

const temporaryDirectories: string[] = [];
function temporaryDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-community-"));
  temporaryDirectories.push(directory);
  return directory;
}
afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  return {
    provider: "gmail",
    accountProof: "private-mailbox-proof-that-must-never-leave-the-client",
    messageId: "private-provider-message-id",
    providerNativeId: "private-provider-native-id",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Hosted report", address: "no-reply@delivery.example", domain: "delivery.example" },
    replyTo: { displayName: "Campaign", address: "reply@scam.example", domain: "scam.example" },
    subject: "Join our exclusive adult community",
    date: new Date(0).toISOString(),
    authentication: { spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview: "Private body content that must never appear in a community report.",
    htmlSignals: { extractedText: "Private body", hrefs: ["https://redirect.example/private/path?id=secret"], hasForm: false, hasPasswordField: false },
    links: [{
      visibleText: "Open",
      rawUrl: "https://redirect.example/private/path?id=secret",
      normalizedUrl: "https://redirect.example/private/path?id=secret",
      claimedBrand: null,
      brandDomainMismatch: null,
    }],
    attachments: [{ fileName: "private.pdf", contentType: "application/pdf", sizeBytes: 100, sha256: "a".repeat(64), hasQrCode: false, qrPayloads: [] }],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 1000, encoding: "multipart", contentCoverage: "complete" },
    ...overrides,
  };
}

function scored(verdict: ScoredMessage["verdict"] = "high_risk", score = 8): ScoredMessage {
  return {
    score,
    verdict,
    confirmedByRule: false,
    layerResults: [],
    evidence: [
      { layer: "message_intent", code: "UNSOLICITED_ADULT_SITE_CAMPAIGN", description: "campaign", scoreContribution: 4, source: "local" },
      { layer: "identity_impersonation", code: "REPLY_TO_MISMATCH", description: "reply", scoreContribution: 2, source: "local" },
      { layer: "global_intelligence", code: "GLOBAL_WARNING_MATCH", description: "must not feed itself", scoreContribution: 3, source: "signed_feed" },
    ],
  };
}

function submission(reporter: string, context = buildCommunityReportContext(envelope(), scored())): CommunityReportSubmission {
  return {
    schemaVersion: 1,
    reporterProof: reporter.padEnd(64, "0").slice(0, 64),
    reportedAt: new Date().toISOString(),
    ...context,
  };
}

describe("privacy-reduced campaign context", () => {
  it("contains useful indicators but no body, subject, mailbox proof, provider ID, raw URL path, or attachment name", () => {
    const message = envelope();
    const context = buildCommunityReportContext(message, scored());
    const serialized = JSON.stringify(context);

    expect(context.campaignFingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(context.indicators).toContainEqual({ type: "campaign", value: context.campaignFingerprint });
    expect(context.indicators).toContainEqual({ type: "reply_to_domain", value: "scam.example" });
    expect(context.indicators).toContainEqual({ type: "url_domain", value: "redirect.example" });
    expect(context.indicators).toContainEqual({ type: "attachment_hash", value: "a".repeat(64) });
    expect(context.indicators.some((item) => item.type === "sender")).toBe(false);
    for (const privateValue of [
      message.subject,
      message.textPreview!,
      message.accountProof,
      message.providerNativeId,
      "private/path",
      "secret",
      "private.pdf",
    ]) expect(serialized).not.toContain(privateValue);
    expect(context.evidenceCodes).not.toContain("GLOBAL_WARNING_MATCH");
  });

  it("publishes a direct non-generic sender address as an exact indicator", () => {
    const message = envelope({
      from: { displayName: "Person", address: "scammer@direct-sender.example", domain: "direct-sender.example" },
    });
    expect(buildCommunityReportContext(message, scored()).indicators)
      .toContainEqual({ type: "sender", value: "scammer@direct-sender.example" });
  });

  it("produces the same campaign fingerprint independently of mailbox and provider identifiers", () => {
    const first = envelope();
    const second = envelope({
      provider: "outlook",
      accountProof: "different-account",
      messageId: "different-id",
      providerNativeId: "different-native-id",
    });
    expect(campaignFingerprint(second)).toBe(campaignFingerprint(first));
  });
});

describe("independent report aggregation", () => {
  it("keeps one report as a candidate and deduplicates the same reporter", () => {
    const directory = temporaryDirectory();
    const store = new EncryptedCommunityAggregateStore(directory);
    const first = store.accept(submission("1"));
    const duplicate = store.accept(submission("1"));

    expect(first).toMatchObject({ status: "candidate", independentReporters: 1, duplicate: false });
    expect(duplicate).toMatchObject({ status: "candidate", independentReporters: 1, duplicate: true });
    expect(store.buildFeedPayload().entries).toEqual([]);
  });

  it("publishes a warning after three independent evidence-bearing reporters", () => {
    const directory = temporaryDirectory();
    const store = new EncryptedCommunityAggregateStore(directory);
    for (const reporter of ["1", "2", "3"]) store.accept(submission(reporter));
    const feed = store.buildFeedPayload();

    expect(feed.entries.length).toBeGreaterThan(0);
    expect(feed.entries.every((item) => item.type === "identity" || item.confirmedThreat === false)).toBe(true);
    expect(feed.entries).toContainEqual(expect.objectContaining({
      type: "campaign",
      value: buildCommunityReportContext(envelope(), scored()).campaignFingerprint,
      independentReports: 3,
    }));
    expect(feed.entries.some((item) => item.type === "sender")).toBe(false);
  });

  it("publishes confirmed indicators only after five reporters and strong evidence thresholds", () => {
    const directory = temporaryDirectory();
    const store = new EncryptedCommunityAggregateStore(directory);
    for (const reporter of ["1", "2", "3", "4", "5"]) store.accept(submission(reporter));
    const feed = store.buildFeedPayload();
    expect(feed.entries.length).toBeGreaterThan(0);
    expect(feed.entries.filter((item) => item.type !== "identity").every((item) => item.confirmedThreat)).toBe(true);
    expect(store.stats().confirmed).toBe(1);
  });

  it("encrypts reporter proofs and campaign indicators at rest", () => {
    const directory = temporaryDirectory();
    const store = new EncryptedCommunityAggregateStore(directory);
    const report = submission("1");
    store.accept(report);
    const encrypted = readFileSync(join(directory, "community-reports.enc.json"), "utf8");
    expect(encrypted).not.toContain(report.reporterProof);
    expect(encrypted).not.toContain(report.campaignFingerprint);
    expect(encrypted).not.toContain("scam.example");
    expect(encrypted).not.toContain("redirect.example");
  });
});

describe("signed feed distribution and enforcement", () => {
  it("accepts a valid fresh feed and rejects tampering and expiry", () => {
    const directory = temporaryDirectory();
    const signer = new CommunityFeedSigner(directory);
    const payload = {
      version: 1 as const,
      generatedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      entries: [],
    };
    const signed = signer.sign(payload);
    expect(verifyCommunityFeed(signed, [signer.publicPem])).toEqual(payload);

    const tampered = structuredClone(signed);
    tampered.payload.entries.push({ type: "sender", value: "fake@example.com", confirmedThreat: true, ruleId: "tampered" });
    expect(verifyCommunityFeed(tampered, [signer.publicPem])).toBeNull();

    const expired = signer.sign({ ...payload, generatedAt: new Date(Date.now() - 120_000).toISOString(), expiresAt: new Date(Date.now() - 60_000).toISOString() });
    expect(verifyCommunityFeed(expired, [signer.publicPem])).toBeNull();
  });

  it("turns a warning feed match into Review and a confirmed match into Confirmed Threat", () => {
    const message = envelope();
    const fingerprint = campaignFingerprint(message);
    const warning = globalIntelligenceLayer(message, {
      getVerifiedEntries: () => [{ type: "campaign", value: fingerprint, confirmedThreat: false, ruleId: "community-warning", independentReports: 3 }],
    });
    expect(warning.confirmedByGlobalRule).toBe(false);
    expect(warning.result.evidence).toContainEqual(expect.objectContaining({ code: "GLOBAL_WARNING_MATCH", scoreContribution: 3 }));

    const confirmed = globalIntelligenceLayer(message, {
      getVerifiedEntries: () => [{ type: "campaign", value: fingerprint, confirmedThreat: true, ruleId: "community-confirmed", independentReports: 5 }],
    });
    expect(confirmed.confirmedByGlobalRule).toBe(true);
    expect(confirmed.result.evidence).toContainEqual(expect.objectContaining({ code: "GLOBAL_CONFIRMED_MATCH", scoreContribution: 10 }));
  });

  it("protects the reporting mailbox immediately through local campaign memory", () => {
    const message = envelope();
    const policy = new InMemoryPersonalPolicyStore();
    const fingerprint = campaignFingerprint(message);
    policy.trustSender(message.from.address!);
    policy.approveException(`message:${"f".repeat(64)}`);
    policy.reportCampaign(fingerprint);
    const result = personalRulesLayer(message, policy);
    expect(result.confirmedByPersonalBlock).toBe(true);
    expect(result.result.evidence).toContainEqual(expect.objectContaining({ code: "LOCALLY_REPORTED_SCAM_CAMPAIGN" }));
  });

  it("uses stable non-reversible reporter proofs and queues failed remote submissions encrypted", async () => {
    const directory = temporaryDirectory();
    const network = new CommunityNetwork({
      dataDirectory: directory,
      remoteUrl: "http://127.0.0.1:1",
      trustedPublicKeys: [],
    });
    const accountKey = "b".repeat(64);
    const proof = network.reporterProof(accountKey);
    expect(proof).toMatch(/^[a-f0-9]{64}$/);
    expect(proof).not.toBe(accountKey);

    const receipt = await network.submit(buildCommunityReportContext(envelope(), scored()), accountKey);
    expect(receipt).toMatchObject({ accepted: true, queued: true, status: "candidate" });
    expect(network.pendingReports()).toBe(1);
    const encrypted = readFileSync(join(directory, "community-outbox.enc.json"), "utf8");
    expect(encrypted).not.toContain(proof);
    expect(encrypted).not.toContain("scam.example");
  });
});
