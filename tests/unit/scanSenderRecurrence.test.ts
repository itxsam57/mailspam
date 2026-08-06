import { describe, expect, it } from "vitest";
import type { EmailAdapter, FetchPage, FolderDescriptor } from "../../server/src/canonical/adapter.js";
import type { CanonicalEnvelope, Provider } from "../../server/src/canonical/envelope.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { quickScan } from "../../server/src/workflows/scanWorkflows.js";

const deps = {
  personalPolicy: new InMemoryPersonalPolicyStore(),
  threatFeed: { getVerifiedEntries: () => [] },
};

function envelope(params: {
  id: string;
  sender: string;
  subject: string;
  replyTo?: string;
  text?: string;
  links?: CanonicalEnvelope["links"];
}): CanonicalEnvelope {
  const senderDomain = params.sender.split("@")[1] ?? null;
  const replyDomain = params.replyTo?.split("@")[1] ?? null;
  return {
    provider: "imap",
    accountProof: "proof",
    messageId: `<${params.id}@test.local>`,
    providerNativeId: params.id,
    folder: "inbox",
    providerFolderName: "INBOX",
    from: {
      displayName: "Example Sender",
      address: params.sender,
      domain: senderDomain,
    },
    replyTo: params.replyTo
      ? { displayName: null, address: params.replyTo, domain: replyDomain }
      : null,
    subject: params.subject,
    date: new Date(0).toISOString(),
    authentication: { spf: "unknown", dkim: "unknown", dmarc: "unknown", arc: "unknown" },
    textPreview: params.text ?? "A normal readable message with enough local content for deterministic analysis.",
    htmlSignals: null,
    links: params.links ?? [],
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: {
      isFirstContact: true,
      threadContinuityBroken: false,
      replyToChangedMidThread: false,
    },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: {
      fetchedAt: new Date(0).toISOString(),
      sizeBytes: 500,
      encoding: "plain",
      contentCoverage: "complete",
    },
  };
}

class PagedAdapter implements EmailAdapter {
  readonly provider: Provider = "imap";
  private offset = 0;

  constructor(readonly pages: CanonicalEnvelope[][]) {}

  async connect(signal: AbortSignal): Promise<void> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
  }

  async listFolders(): Promise<FolderDescriptor[]> {
    return [{ providerFolderName: "INBOX", normalized: "inbox", includedByDefault: true }];
  }

  async fetchPage(): Promise<FetchPage> {
    const envelopes = this.pages[this.offset] ?? [];
    this.offset++;
    const done = this.offset >= this.pages.length;
    return {
      envelopes,
      nextCursor: done ? null : String(this.offset),
      done,
    };
  }

  async moveToTrash(): Promise<void> {}

  async reportSpam(messageIds: string[]) {
    return {
      requested: messageIds.length,
      reported: messageIds.length,
      mode: "fixture_junk_move" as const,
    };
  }

  async disconnect(): Promise<void> {}
}

async function run(adapter: EmailAdapter) {
  const events = [];
  for await (const event of quickScan(
    adapter,
    deps,
    new AbortController().signal,
    1,
    10,
  )) {
    events.push(event);
  }
  return events;
}

describe("scan-local sender recurrence", () => {
  it("does not repeat a first-contact reward warning for a sender already seen earlier in the scan", async () => {
    const first = envelope({
      id: "normal",
      sender: "news@merchant.example",
      subject: "Your monthly account update",
    });
    const recurringReward = envelope({
      id: "reward",
      sender: "news@merchant.example",
      subject: "Claim your free loyalty reward",
    });

    const events = await run(new PagedAdapter([[first], [recurringReward]]));
    const final = events.at(-1)!;

    expect(first.threadContext.senderPreviouslySeenInScan).toBe(false);
    expect(recurringReward.threadContext.senderPreviouslySeenInScan).toBe(true);
    expect(final.diagnosticSummaries[0]?.evidenceCodes).not.toContain("FREE_REWARD_LURE");
    expect(final.counters.review).toBe(0);
  });

  it("keeps the reward warning for a genuinely unseen sender", async () => {
    const first = envelope({
      id: "normal",
      sender: "news@merchant.example",
      subject: "Your monthly account update",
    });
    const unseenReward = envelope({
      id: "reward",
      sender: "offer@different-sender.example",
      subject: "Claim your free loyalty reward",
    });

    const events = await run(new PagedAdapter([[first], [unseenReward]]));
    const final = events.at(-1)!;

    expect(unseenReward.threadContext.senderPreviouslySeenInScan).toBe(false);
    expect(final.diagnosticSummaries[0]?.evidenceCodes).toContain("FREE_REWARD_LURE");
    expect(final.counters.review).toBe(1);
  });

  it("does not weaken high-confidence adult-campaign detection for a repeated transport sender", async () => {
    const first = envelope({
      id: "normal",
      sender: "notifications@platform.example",
      subject: "A normal platform notification",
    });
    const adultCampaign = envelope({
      id: "adult",
      sender: "notifications@platform.example",
      replyTo: "reply@unrelated-campaign.example",
      subject: "Join our exclusive adult community",
      text: "Join our exclusive adult community and view private photos.",
      links: [{
        visibleText: "Join now",
        rawUrl: "https://unrelated-campaign.example/join",
        normalizedUrl: "https://unrelated-campaign.example/join",
        claimedBrand: null,
        brandDomainMismatch: null,
      }],
    });

    const events = await run(new PagedAdapter([[first], [adultCampaign]]));
    const final = events.at(-1)!;

    expect(adultCampaign.threadContext.senderPreviouslySeenInScan).toBe(true);
    expect(final.diagnosticSummaries[0]?.evidenceCodes).toContain("UNSOLICITED_ADULT_SITE_CAMPAIGN");
    expect(final.counters.highRisk).toBe(1);
  });
});
