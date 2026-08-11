import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = join(import.meta.dirname, "../..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("community shield architecture", () => {
  it("keeps provider Junk movement separate from shared Report Scam", () => {
    const review = read("web/review-actions.js");
    const server = read("server/src/api/server.ts");
    expect(review).toContain("Report Scam to Email Shield");
    expect(review).toContain("Move to Spam/Junk");
    expect(review).toContain("This did not submit community intelligence");
    expect(server).toContain('/messages/report-scam');
    expect(server).toContain('/messages/report-spam');
  });

  it("never exposes report payload fields or reporter proofs to browser code", () => {
    for (const path of ["web/review-actions.js", "web/safe-audit.js", "web/scan-monitor.js"]) {
      const content = read(path);
      expect(content).not.toContain("campaignFingerprint");
      expect(content).not.toContain("reporterProof");
      expect(content).not.toContain("action.communityReport");
    }
    for (const path of ["web/review-actions.js", "web/safe-audit.js"]) {
      expect(read(path)).not.toContain("providerNativeIds");
    }
    const server = read("server/src/api/server.ts");
    expect(server).toContain("delete summary.actionContext");
  });

  it("requires independent reporters and weighted evidence before publishing", () => {
    const store = read("server/src/community/aggregateStore.ts");
    expect(store).toContain("warningReporters: 3");
    expect(store).toContain("confirmedReporters: 5");
    expect(store).toContain("confirmedStrongReporters: 3");
    expect(store).toContain("MAX_REPORTS_PER_REPORTER_PER_DAY");
    expect(store).toContain("duplicate");
  });

  it("uses signed fresh feeds and refuses invalid or expired intelligence", () => {
    const signing = read("server/src/community/signing.ts");
    const network = read("server/src/community/network.ts");
    expect(signing).toContain('generateKeyPairSync("ed25519")');
    expect(signing).toContain('algorithm: "Ed25519"');
    expect(signing).toContain("expiresAt <= now.getTime()");
    expect(network).toContain("verifyCommunityFeed");
    expect(network).toContain("this.verifiedEntries = cached?.entries ?? null");
  });

  it("passes only verified entries into the provider-neutral scan worker", () => {
    const server = read("server/src/api/server.ts");
    const worker = read("server/src/workers/scanWorker.ts");
    expect(server).toContain("await community.refreshFeed()");
    expect(server).toContain("threatFeedEntries: community.getVerifiedEntries()");
    expect(worker).toContain("threatFeedEntries?: SignedFeedEntry[] | null");
    expect(worker).toContain("getVerifiedEntries: () => entries");
  });

  it("supports a self-hosted central service without enabling public ingestion by default", () => {
    const network = read("server/src/community/network.ts");
    const errors = read("server/src/community/errors.ts");
    const publicServer = read("server/src/community/server.ts");
    const desktopServer = read("server/src/api/server.ts");
    expect(network).toContain('process.env.EMAIL_SHIELD_COMMUNITY_SERVER === "1"');
    expect(network).toContain('import { CommunityServiceDisabledError } from "./errors.js"');
    expect(network).toContain("throw new CommunityServiceDisabledError()");
    expect(errors).toContain("export class CommunityServiceDisabledError extends Error");
    expect(publicServer).toContain("error instanceof CommunityServiceDisabledError");
    expect(publicServer).toContain('sendPublicError(res, 503, "service_unavailable")');
    expect(desktopServer).toContain('/api/community/v1/report');
    expect(desktopServer).toContain('/api/community/v1/feed');
    expect(desktopServer).toContain('/api/community/v1/public-key');
  });

  it("stores local campaign protection and pending reports encrypted", () => {
    const policy = read("server/src/api/policyPersistence.ts");
    const outbox = read("server/src/community/outbox.ts");
    const aggregate = read("server/src/community/aggregateStore.ts");
    expect(policy).toContain("reportedCampaigns");
    expect(outbox).toContain('const ALGORITHM = "aes-256-gcm"');
    expect(aggregate).toContain('const ALGORITHM = "aes-256-gcm"');
    expect(outbox).not.toContain("textPreview");
    expect(aggregate).not.toContain("textPreview");
  });
});
