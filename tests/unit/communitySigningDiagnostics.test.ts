import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { CommunityFeedSigner, inspectCommunityFeed } from "../../server/src/community/signing.js";

const directories: string[] = [];
afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function signer(): CommunityFeedSigner {
  const directory = mkdtempSync(join(tmpdir(), "email-shield-signing-diagnostics-"));
  directories.push(directory);
  return new CommunityFeedSigner(directory);
}

describe("community feed verification diagnostics", () => {
  it("self-signed fresh documents verify without a rejection reason", () => {
    const feedSigner = signer();
    const generatedAt = new Date();
    const payload = {
      version: 1 as const,
      generatedAt: generatedAt.toISOString(),
      expiresAt: new Date(generatedAt.getTime() + 5 * 60_000).toISOString(),
      entries: [],
    };
    const document = feedSigner.sign(payload);
    const result = inspectCommunityFeed(
      document,
      [feedSigner.publicPem],
      new Date(generatedAt.getTime() + 1),
    );
    expect(result.reason).toBeNull();
    expect(result.payload).toEqual(payload);
  });

  it("distinguishes untrusted keys from signature tampering", () => {
    const trustedSigner = signer();
    const otherSigner = signer();
    const generatedAt = new Date();
    const payload = {
      version: 1 as const,
      generatedAt: generatedAt.toISOString(),
      expiresAt: new Date(generatedAt.getTime() + 5 * 60_000).toISOString(),
      entries: [],
    };
    const document = trustedSigner.sign(payload);
    expect(inspectCommunityFeed(document, [otherSigner.publicPem], generatedAt).reason).toBe("untrusted_key");

    const tampered = structuredClone(document);
    tampered.payload.entries.push({
      type: "sender",
      value: "tampered@example.test",
      confirmedThreat: true,
      ruleId: "tampered",
    });
    expect(inspectCommunityFeed(tampered, [trustedSigner.publicPem], generatedAt).reason).toBe("signature_mismatch");
  });
});
