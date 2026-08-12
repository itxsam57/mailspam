import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dirname, "../..");
const localDesktop = readFileSync(join(root, "server/src/api/localDesktopServer.ts"), "utf8");
const familyAware = readFileSync(join(root, "server/src/api/familyAwareScanStream.ts"), "utf8");
const background = readFileSync(join(root, "server/src/api/backgroundProtection.ts"), "utf8");
const startup = readFileSync(join(root, "server/src/index.ts"), "utf8");

describe("Family Shield manual/background/realtime scan parity", () => {
  it("uses account-scoped family-aware handlers for both new and resumed manual scans", () => {
    expect(localDesktop).toContain("createFamilyAwareScanStreamHandler({ community, accountPlatform })");
    expect(localDesktop).toContain("createFamilyAwareResumeScanStreamHandler({ community, accountPlatform })");
    expect(familyAware).toContain("service.familyThreatSnapshot(mailboxAccountKey)");
    expect(familyAware).toContain("mergeVerifiedAndFamilyIntelligence");
    expect(familyAware).not.toContain("community.getVerifiedEntries =");
  });

  it("injects the same account platform into the Worker shared by scheduled and realtime protection", () => {
    expect(startup).toContain("new WorkerBackgroundProtectionExecutor(communityNetwork, accountPlatform)");
    expect(startup).toContain("const protectionExecutor = new SerialProtectionExecutor(workerProtectionExecutor)");
    expect(startup).toContain("executor: protectionExecutor");
    expect(startup).toContain("new RealtimeProtectionProcessor(sessionStore, protectionExecutor)");
    expect(background).toContain("this.accountPlatform.familyThreatSnapshot(session.policyAccountKey)");
    expect(background).toContain("mergeVerifiedAndFamilyIntelligence");
  });

  it("keeps a failed global signed feed fail-closed in manual, scheduled and realtime paths", () => {
    expect(familyAware).toContain("mergeVerifiedAndFamilyIntelligence");
    expect(background).toContain("mergeVerifiedAndFamilyIntelligence");
    const adapter = readFileSync(join(root, "server/src/platform/familyThreatFeedAdapter.ts"), "utf8");
    expect(adapter).toContain("if (verifiedEntries === null) return null");
  });
});
