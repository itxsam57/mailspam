import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope, Provider } from "../../server/src/canonical/envelope.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import type { SignedFeedEntry } from "../../server/src/engine/layers/globalIntelligence.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";

const providers: Provider[] = ["gmail", "icloud", "yahoo", "imap", "outlook"];
const root = join(import.meta.dirname, "../..");

function envelope(provider: Provider, overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  return {
    provider,
    accountProof: `provider-parity-${provider}`,
    messageId: `provider-parity-message-${provider}`,
    providerNativeId: `provider-parity-native-${provider}`,
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Cobalt Tools", address: "notice@cobalt-tools.example", domain: "cobalt-tools.example" },
    replyTo: null,
    subject: "Cobalt Tools notice",
    date: new Date(0).toISOString(),
    authentication: {
      providerTrust: "trusted",
      spf: "pass",
      dkim: "pass",
      dmarc: "pass",
      arc: "none",
    },
    textPreview: "Normal product and account information from Cobalt Tools.",
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 1024, encoding: "plain", contentCoverage: "complete" },
    ...overrides,
  };
}

function scan(message: CanonicalEnvelope) {
  return scanMessage(message, {
    personalPolicy: new InMemoryPersonalPolicyStore(),
    threatFeed: { getVerifiedEntries: () => [] as SignedFeedEntry[] },
  });
}

function decision(result: ReturnType<typeof scan>) {
  return {
    verdict: result.scored.verdict,
    score: result.scored.score,
    codes: result.scored.evidence.map((item) => item.code).sort(),
  };
}

describe("universal provider-neutral detection parity", () => {
  it("returns identical scam decisions when normalized decision evidence is identical", () => {
    const messages = providers.map((provider) => envelope(provider, {
      from: { displayName: "Project Manager", address: "manager@work.example", domain: "work.example" },
      subject: "Private purchase request",
      textPreview: "Buy $500 in Apple gift cards today. Send clear photos of the codes. Do not call; keep this between us.",
    }));
    const results = messages.map(scan);
    const reference = decision(results[0]!);

    expect(reference.verdict).toBe("high_risk");
    expect(reference.codes).toContain("GIFT_CARD_CODE_EXFILTRATION");
    for (const result of results.slice(1)) expect(decision(result)).toEqual(reference);
  });

  it("returns identical benign decisions when normalized decision evidence is identical", () => {
    const results = providers.map((provider) => scan(envelope(provider, {
      subject: "Documentation update",
      textPreview: "The documentation index was refreshed. No payment, credential, remote-access, or account action is requested.",
    })));
    const reference = decision(results[0]!);

    expect(reference.verdict).toBe("safe");
    for (const result of results.slice(1)) expect(decision(result)).toEqual(reference);
  });

  it("allows provider-normalized facts such as Spam placement to change evidence without branching on provider identity", () => {
    const inbox = scan(envelope("gmail", {
      authentication: { providerTrust: "unknown", spf: "unknown", dkim: "unknown", dmarc: "unknown", arc: "unknown" },
    }));
    const spam = scan(envelope("icloud", {
      folder: "spam",
      providerFolderName: "Junk",
      authentication: { providerTrust: "unknown", spf: "unknown", dkim: "unknown", dmarc: "unknown", arc: "unknown" },
    }));

    expect(inbox.scored.evidence.some((item) => item.code === "PROVIDER_SPAM_JUNK_PLACEMENT")).toBe(false);
    expect(spam.scored.evidence).toContainEqual(expect.objectContaining({
      code: "PROVIDER_SPAM_JUNK_PLACEMENT",
      scoreContribution: 2,
    }));
  });

  it("keeps provider-specific decision branches out of the shared detector", () => {
    const sharedFiles = [
      "server/src/engine/pipeline.ts",
      "server/src/engine/verdict.ts",
      "server/src/engine/structuralScamEvidence.ts",
      "server/src/engine/layers/structuralConsistency.ts",
      "server/src/engine/layers/messageIntent.ts",
      "server/src/engine/layers/identityImpersonation.ts",
      "server/src/engine/layers/linkStructure.ts",
      "server/src/engine/layers/transportAuth.ts",
    ];
    const forbidden = providers.map((provider) => `envelope.provider === \"${provider}\"`);

    for (const file of sharedFiles) {
      const source = readFileSync(join(root, file), "utf8");
      for (const branch of forbidden) expect(source, `${file} must not contain ${branch}`).not.toContain(branch);
    }
  });
});
