import { describe, expect, it } from "vitest";
import type { EmailAdapter } from "../../server/src/canonical/adapter.js";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { identityImpersonationLayer } from "../../server/src/engine/layers/identityImpersonation.js";
import { linkStructureLayer } from "../../server/src/engine/layers/linkStructure.js";
import { messageIntentLayer } from "../../server/src/engine/layers/messageIntent.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { quickScan } from "../../server/src/workflows/scanWorkflows.js";

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  return {
    provider: "imap",
    accountProof: "proof",
    messageId: "message-id",
    providerNativeId: "native-id",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: {
      displayName: "Example Service",
      address: "news@mail.example-service.example",
      domain: "mail.example-service.example",
    },
    replyTo: null,
    subject: "Example Service update",
    date: new Date(0).toISOString(),
    authentication: { spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview: "A normal readable message used to verify context-aware deterministic rules. ".repeat(4),
    htmlSignals: null,
    links: [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: {
      fetchedAt: new Date(0).toISOString(),
      sizeBytes: 1000,
      encoding: "plain",
      contentCoverage: "complete",
    },
    ...overrides,
  };
}

function evidenceCodes(result: ReturnType<typeof identityImpersonationLayer> | ReturnType<typeof linkStructureLayer> | ReturnType<typeof messageIntentLayer>): string[] {
  return result.evidence.map((item) => item.code);
}

describe("context-aware identity claims", () => {
  it("does not treat a dotted social username as an asserted web domain", () => {
    const result = identityImpersonationLayer(envelope({
      from: {
        displayName: "Creator updates on Social Network",
        address: "notifications@social-network.example",
        domain: "social-network.example",
      },
      subject: "whoisalex.exe, catch up on moments you missed",
    }));

    expect(evidenceCodes(result)).not.toContain("EXPLICIT_DOMAIN_CLAIM_MISMATCH");
  });

  it("still detects a domain when language explicitly presents it as a destination", () => {
    const result = identityImpersonationLayer(envelope({
      from: {
        displayName: "Account notice",
        address: "notice@unrelated-sender.example",
        domain: "unrelated-sender.example",
      },
      subject: "Continue at secure-login.example to verify payment",
    }));

    expect(evidenceCodes(result)).toContain("EXPLICIT_DOMAIN_CLAIM_MISMATCH");
  });

  it("does not reinterpret a repeated human name in a social notification as a brand", () => {
    const result = identityImpersonationLayer(envelope({
      from: {
        displayName: "Avery Morgan on Social Network",
        address: "notifications@social-network.example",
        domain: "social-network.example",
      },
      subject: "Avery Morgan is in your phone contacts",
    }));

    expect(evidenceCodes(result)).not.toContain("BRAND_DOMAIN_MISMATCH");
  });

  it("keeps generic transactional organization impersonation detection", () => {
    const result = identityImpersonationLayer(envelope({
      from: {
        displayName: "Cobalt Bank Security",
        address: "notice@unrelated-sender.example",
        domain: "unrelated-sender.example",
      },
      subject: "Cobalt Bank payment verification required",
    }));

    expect(evidenceCodes(result)).toContain("BRAND_DOMAIN_MISMATCH");
  });
});

describe("context-aware link structure", () => {
  it("accepts a non-sensitive HTTPS tracking redirect in authenticated bulk mail", () => {
    const result = linkStructureLayer(envelope({
      from: {
        displayName: "Vendor News",
        address: "news@mail.vendor.example",
        domain: "mail.vendor.example",
      },
      subject: "Vendor research invitation",
      listHeaders: {
        listId: "news.vendor.example",
        listUnsubscribe: "<https://vendor.example/unsubscribe>",
        listUnsubscribePost: null,
      },
      links: [{
        visibleText: "https://www.vendor.example",
        rawUrl: "https://click.delivery-platform.example/campaign/123",
        normalizedUrl: "https://click.delivery-platform.example/campaign/123",
        claimedBrand: null,
        brandDomainMismatch: null,
      }],
    }));

    expect(evidenceCodes(result)).not.toContain("DISPLAYED_VS_ACTUAL_MISMATCH");
  });

  it("keeps displayed-domain mismatch detection without authenticated bulk-mail context", () => {
    const result = linkStructureLayer(envelope({
      from: {
        displayName: "Vendor News",
        address: "news@unrelated.example",
        domain: "unrelated.example",
      },
      authentication: { spf: "fail", dkim: "fail", dmarc: "fail", arc: "none" },
      links: [{
        visibleText: "https://www.vendor.example",
        rawUrl: "https://click.delivery-platform.example/campaign/123",
        normalizedUrl: "https://click.delivery-platform.example/campaign/123",
        claimedBrand: null,
        brandDomainMismatch: null,
      }],
    }));

    expect(evidenceCodes(result)).toContain("DISPLAYED_VS_ACTUAL_MISMATCH");
  });

  it("ignores ordinary fragment placeholders instead of calling them malformed URLs", () => {
    const result = linkStructureLayer(envelope({
      links: [{
        visibleText: "",
        rawUrl: "#",
        normalizedUrl: "#",
        claimedBrand: null,
        brandDomainMismatch: null,
      }],
    }));

    expect(evidenceCodes(result)).not.toContain("MALFORMED_URL");
  });

  it("still blocks executable link schemes", () => {
    const result = linkStructureLayer(envelope({
      links: [{
        visibleText: "Open",
        rawUrl: "javascript:alert(1)",
        normalizedUrl: "javascript:alert(1)",
        claimedBrand: null,
        brandDomainMismatch: null,
      }],
    }));

    expect(evidenceCodes(result)).toContain("UNSAFE_LINK_SCHEME");
  });

  it("does not warn about a shortener alone in authenticated non-sensitive organizational mail", () => {
    const result = linkStructureLayer(envelope({
      links: [{
        visibleText: "View activity",
        rawUrl: "https://t.co/example",
        normalizedUrl: "https://t.co/example",
        claimedBrand: null,
        brandDomainMismatch: null,
      }],
    }));

    expect(evidenceCodes(result)).not.toContain("URL_SHORTENER");
  });

  it("keeps shortener evidence for unauthenticated mail", () => {
    const result = linkStructureLayer(envelope({
      authentication: { spf: "fail", dkim: "fail", dmarc: "fail", arc: "none" },
      links: [{
        visibleText: "View activity",
        rawUrl: "https://t.co/example",
        normalizedUrl: "https://t.co/example",
        claimedBrand: null,
        brandDomainMismatch: null,
      }],
    }));

    expect(evidenceCodes(result)).toContain("URL_SHORTENER");
  });
});

describe("subscription and coverage context", () => {
  it("does not call an authenticated mailing-list reward promotion an unsolicited first-contact lure", () => {
    const result = messageIntentLayer(envelope({
      subject: "Claim your free loyalty reward",
      listHeaders: {
        listId: "promotions.example-service.example",
        listUnsubscribe: "<https://example-service.example/unsubscribe>",
        listUnsubscribePost: null,
      },
    }));

    expect(evidenceCodes(result)).not.toContain("FREE_REWARD_LURE");
  });

  it("keeps the same reward rule for first-contact personal or unauthenticated mail", () => {
    const result = messageIntentLayer(envelope({
      from: { displayName: "Rewards", address: "reward@gmail.com", domain: "gmail.com" },
      authentication: { spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
      subject: "Claim your free tool set",
    }));

    expect(evidenceCodes(result)).toContain("FREE_REWARD_LURE");
  });

  it("presents safely bounded MIME as bounded sufficient without repeating the cap note", async () => {
    const bounded = envelope({
      parseStatus: "partial",
      parseNotes: ["Readable MIME content was bounded to 24576 decoded characters per alternative."],
      diagnostics: {
        fetchedAt: new Date(0).toISOString(),
        sizeBytes: 60000,
        encoding: "multipart",
        contentCoverage: "bounded_sufficient",
      },
    });

    const adapter: EmailAdapter = {
      provider: "imap",
      connect: async () => {},
      listFolders: async () => [{ providerFolderName: "INBOX", normalized: "inbox", includedByDefault: true }],
      fetchPage: async () => ({ envelopes: [bounded], nextCursor: null, done: true }),
      moveToTrash: async () => {},
      reportSpam: async () => ({ requested: 0, reported: 0, mode: "fixture_junk_move" }),
      disconnect: async () => {},
    };

    const pages = [];
    for await (const page of quickScan(
      adapter,
      {
        personalPolicy: new InMemoryPersonalPolicyStore(),
        threatFeed: { getVerifiedEntries: () => [] },
      },
      new AbortController().signal,
      1,
      1,
    )) pages.push(page);

    expect(pages).toHaveLength(1);
    expect(pages[0]!.diagnosticSummaries[0]).toMatchObject({
      parseStatus: "bounded sufficient",
      contentCoverage: "bounded_sufficient",
      parseNotes: [],
    });
  });
});
