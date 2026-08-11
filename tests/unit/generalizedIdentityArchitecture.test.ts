import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import {
  authenticatedSenderIdentityDomains,
  hasAuthenticatedOrganizationalIdentity,
  verifiedRelayOriginDomains,
} from "../../server/src/engine/identitySignals.js";
import { identityImpersonationLayer } from "../../server/src/engine/layers/identityImpersonation.js";
import {
  globalIntelligenceLayer,
  type SignedFeedEntry,
} from "../../server/src/engine/layers/globalIntelligence.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  return {
    provider: "imap",
    accountProof: "proof",
    messageId: "message-id",
    providerNativeId: "native-id",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Northwind Labs", address: "news@mail.northwind.example", domain: "mail.northwind.example" },
    replyTo: null,
    subject: "Northwind Labs account update",
    date: new Date(0).toISOString(),
    authentication: { providerTrust: "trusted", spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview: "This is a readable account notification from a fictional organization used only for tests. ".repeat(4),
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 1000, encoding: "plain", contentCoverage: "complete" },
    ...overrides,
  };
}

const emptyFeed = { getVerifiedEntries: () => [] as SignedFeedEntry[] };
const deps = () => ({ personalPolicy: new InMemoryPersonalPolicyStore(), threatFeed: emptyFeed });

describe("unknown-organization identity", () => {
  it("trusts any authenticated aligned organizational domain without prior brand knowledge", () => {
    const message = envelope({
      from: { displayName: "Cobalt University", address: "registrar@notices.cobalt-university.example", domain: "notices.cobalt-university.example" },
      subject: "Cobalt University enrollment update",
    });
    expect(authenticatedSenderIdentityDomains(message)).toEqual(["cobalt-university.example"]);
    expect(hasAuthenticatedOrganizationalIdentity(message)).toBe(true);
  });

  it("does not treat a shared personal mailbox as an organization", () => {
    const message = envelope({
      from: { displayName: "Cobalt University", address: "cobalt-office@gmail.com", domain: "gmail.com" },
    });
    expect(authenticatedSenderIdentityDomains(message)).toEqual([]);
  });

  it("decodes a previously unseen authenticated relay origin from format, not a brand list", () => {
    const message = envelope({
      from: {
        displayName: "Lumen Market",
        address: "newsletter_at_updates_lumen-market_example_random9@privaterelay.appleid.com",
        domain: "privaterelay.appleid.com",
      },
      subject: "Lumen Market weekly update",
    });
    expect(verifiedRelayOriginDomains(message)).toContain("lumen-market.example");
  });

  it("allows bounded mail from a new authenticated organization to resolve Safe", () => {
    const result = scanMessage(envelope({
      from: { displayName: "Orbit Tools", address: "news@mailer.orbit-tools.example", domain: "mailer.orbit-tools.example" },
      subject: "Orbit Tools product newsletter",
      textPreview: "Product updates, documentation, and account preferences are available in your dashboard.",
      parseStatus: "partial",
      parseNotes: ["Readable text was bounded to 24576 bytes."],
      diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 60000, encoding: "multipart", contentCoverage: "bounded_sufficient" },
    }), deps());
    expect(result.scored.verdict).toBe("safe");
  });
});

describe("generic identity-claim mismatch", () => {
  it("flags an explicit claimed domain unrelated to the sender", () => {
    const result = identityImpersonationLayer(envelope({
      from: { displayName: "Billing at cobalt-bank.example", address: "notice@unrelated-sender.example", domain: "unrelated-sender.example" },
      subject: "Account payment alert",
    }));
    expect(result.evidence).toContainEqual(expect.objectContaining({
      code: "EXPLICIT_DOMAIN_CLAIM_MISMATCH",
      scoreContribution: 4,
    }));
  });

  it("flags a repeated organization-like transactional claim without knowing the organization first", () => {
    const result = identityImpersonationLayer(envelope({
      from: { displayName: "Cobalt Bank Security", address: "notice@unrelated-sender.example", domain: "unrelated-sender.example" },
      subject: "Cobalt Bank payment verification required",
    }));
    expect(result.evidence.some((item) => item.code === "BRAND_DOMAIN_MISMATCH")).toBe(true);
  });

  it("accepts the same claim when independent message metadata supports the organization", () => {
    const result = identityImpersonationLayer(envelope({
      from: { displayName: "Cobalt Bank Security", address: "mail@delivery-vendor.example", domain: "delivery-vendor.example" },
      subject: "Cobalt Bank payment update",
      replyTo: { displayName: null, address: "help@cobalt-bank.example", domain: "cobalt-bank.example" },
      listHeaders: { listId: "notices.cobalt-bank.example", listUnsubscribe: null, listUnsubscribePost: null },
    }));
    expect(result.evidence.some((item) => item.code === "BRAND_DOMAIN_MISMATCH")).toBe(false);
  });
});

describe("updateable signed identity knowledge", () => {
  const identityEntry: SignedFeedEntry = {
    type: "identity",
    value: "Aurora Credit Union",
    aliases: ["Aurora CU"],
    domains: ["aurora-credit.example"],
    confirmedThreat: false,
    ruleId: "identity-aurora-v1",
  };

  it("detects a known identity impersonation from signed data without code changes", () => {
    const feed = { getVerifiedEntries: () => [identityEntry] };
    const { result } = globalIntelligenceLayer(envelope({
      from: { displayName: "Aurora Credit Union", address: "alerts@attacker.example", domain: "attacker.example" },
      subject: "Aurora CU account notice",
    }), feed);
    expect(result.evidence).toContainEqual(expect.objectContaining({
      code: "SIGNED_IDENTITY_DOMAIN_MISMATCH",
      source: "signed_feed",
    }));
  });

  it("accepts the same signed identity when the authenticated domain aligns", () => {
    const feed = { getVerifiedEntries: () => [identityEntry] };
    const { result } = globalIntelligenceLayer(envelope({
      from: { displayName: "Aurora Credit Union", address: "alerts@mail.aurora-credit.example", domain: "mail.aurora-credit.example" },
      subject: "Aurora CU account notice",
    }), feed);
    expect(result.evidence.some((item) => item.code === "SIGNED_IDENTITY_DOMAIN_MISMATCH")).toBe(false);
  });
});

describe("architecture boundary", () => {
  it("keeps brand mappings out of MIME and local identity code", () => {
const root = join(import.meta.dirname, "../..");
    const mime = readFileSync(join(root, "server/src/util/mimeNormalize.ts"), "utf8");
    const htmlInteractions = readFileSync(join(root, "server/src/util/htmlInteraction.ts"), "utf8");
    const identity = readFileSync(join(root, "server/src/engine/layers/identityImpersonation.ts"), "utf8");
    const links = readFileSync(join(root, "server/src/engine/layers/linkStructure.ts"), "utf8");

    expect(mime).not.toContain("OFFICIAL_BRAND_DOMAINS");
    expect(mime).not.toContain("claimedBrandFromText");
    expect(htmlInteractions).not.toContain("OFFICIAL_BRAND_DOMAINS");
    expect(htmlInteractions).not.toContain("claimedBrandFromText");
    expect(htmlInteractions).toContain("claimedBrand: null");
    expect(identity).toContain("Object.freeze({})");
    expect(identity).not.toContain('paypal: [');
    expect(identity).not.toContain('redotpay: [');
    expect(identity).not.toContain('foodpanda: [');
    expect(links).not.toContain("link.claimedBrand");
    expect(links).not.toContain("brandDomainMismatch");
  });
});
