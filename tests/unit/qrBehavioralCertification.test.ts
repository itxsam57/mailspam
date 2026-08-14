import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope, LinkInfo, Provider } from "../../server/src/canonical/envelope.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import type { ThreatFeedCache } from "../../server/src/engine/layers/globalIntelligence.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";
import { analyzeQrImages } from "../../server/src/util/qrDecode.js";

const QR_URL = "https://secure-login.example.test/verify?session=qr123";
const URL_QR_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAZoAAAGaAQAAAAAefbjOAAAC/0lEQVR4nO2cS26kMBCGvxoj9RKkHKCPYm42miPNDeAofYCR8LIlo5qFH9DJYhT1BDpQXhA68KltpVSPv+yI8ukx/vg8AwYZZJBBBhlk0DEhyaOBsdxJH0REulkglBf6XaZn0IYQqqqKV1XVyeXLAOiA0/x0qneqqsOLr8mgZ6Am/wwd+N8ggEA7IX7qZHlRwMXNp2fQC0BtRPXWwNhBcg/D13yTQa8INe9/4YcZaO+iMDc6Xu/yQbJ48TUZ9AxULKJVIACjOIXQIX5wKnBJBrE2ixdfk0H/AUoVRgf4CaTHKYSmfpxTqbHX9Aza2kc8xIVZFO6iENGxQ7IH2WN6Bm0OlepzAsCpDrgcJoZWy6hP1arPo0PZIgDwGlFNF9VyF1GdsjxhesTxoWoRi2eIyTZILqPVdFlkKrOIQ0M1arjkFEjBYWJtFjo5xaLGOaB11AAeQsdEUajaSJauzCKODpU/cu1h0EYWkTLZxkAxC8sjzgJ5vQujiKjeGqRvc+OLUS4rD5JN5XusyaDnFKpsB9K3ER1Cg/TMtdM1i/Sh2sb3WJNBz0SNmlSmS84eSoc85xHWDT8DVPKIJW0sd+mx15xWpIBhFnF4qNpBlSbbagKLCjGROhxWaxwfqt3wuVFaJWcO7Z9GoImlrxEbxg7ED9tOz6DdoNAAQUSHlEA6xetd5OfkStejVbVa4/hQyRmK2LBKHKpwmfUI62ucAlr1PnPuuEocFu06VjHTLOLgUN2LXTue0/pBLjyx3udpoNXu/He7bBc9In02H3EOqCpUeWQvQMkn/cpeMD3iBFCqPota7aIS3qJ4nUUJLgqhA8Jbih269fQM2hx6f6aLZe9MUrZrEVJfNh9xCiiUQ51+miULEOGScgtGEUm2sdf0DNoPGq+q+usaEbne0yHg1OQi9UN3np5Bm0P+JoK/XR7KjJtIkal2np5BXw19OBs+wLrCgCJF2D7Lc0CP+yyXzNLl/XWLYLVqmL/4mgx6Bvp4zPffw/4zmUEGGWSQQQYZBPAXKTC92Jh9hUIAAAAASUVORK5CYII=",
  "base64",
);

function baseEnvelope(provider: Provider = "gmail", links: LinkInfo[] = []): CanonicalEnvelope {
  return {
    provider,
    accountProof: `qr-proof-${provider}`,
    messageId: `<qr-cert-${provider}@example.test>`,
    providerNativeId: `qr-native-${provider}`,
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Routine Sender", address: "routine@example.test", domain: "example.test" },
    replyTo: null,
    subject: "Routine message",
    date: "2026-08-14T10:00:00.000Z",
    authentication: { spf: "pass", dkim: "pass", dmarc: "pass", arc: "none", providerTrust: "trusted" },
    textPreview: "Routine authenticated correspondence with enough ordinary context to establish readable complete content and no urgent payment or credential request.",
    htmlSignals: null,
    links,
    attachments: [],
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: {
      isFirstContact: false,
      threadContinuityBroken: false,
      replyToChangedMidThread: false,
      relationshipPriorMessages: 10,
      relationshipPriorAuthenticatedMessages: 10,
      relationshipPriorSafeMessages: 10,
      relationshipPriorSuspiciousMessages: 0,
      hasEstablishedSenderHistory: true,
      relationshipAuthenticationDowngrade: false,
      replyToChangedFromRelationshipHistory: false,
    },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: { fetchedAt: "2026-08-14T10:00:00.000Z", sizeBytes: 512, encoding: "plain", contentCoverage: "complete" },
  };
}

const emptyFeed: ThreatFeedCache = { getVerifiedEntries: () => [] };
function confirmedUrlFeed(url: string): ThreatFeedCache {
  return {
    getVerifiedEntries: () => [{
      type: "url",
      value: url,
      confirmedThreat: true,
      ruleId: "certified-malicious-qr-url",
      independentReports: 5,
    }],
  };
}

function decodedQrLinks(): LinkInfo[] {
  const analysis = analyzeQrImages([{ name: "security-qr.png", mimeType: "image/png", content: URL_QR_PNG }]);
  expect(analysis.incomplete).toBe(false);
  expect(analysis.results).toEqual([{ name: "security-qr.png", status: "decoded_url", url: QR_URL }]);
  expect(analysis.links).toHaveLength(1);
  expect(analysis.links[0]).toMatchObject({ normalizedUrl: QR_URL, rawUrl: QR_URL, source: "qr" });
  return analysis.links;
}

describe("QR behavioral certification", () => {
  it("carries a URL decoded from real PNG pixels into the final engine and escalates the suspicious hidden destination", () => {
    const result = scanMessage(baseEnvelope("gmail", decodedQrLinks()), {
      personalPolicy: new InMemoryPersonalPolicyStore(),
      threatFeed: emptyFeed,
    });

    expect(result.scored.verdict).toBe("high_risk");
    expect(result.action).toBe("allow_one_click_block");
    expect(result.scored.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ layer: "link_structure", code: "LINK_EMBEDDED_IN_QR" }),
      expect.objectContaining({ layer: "attachment_qr", code: "QR_CODE_URL_PAYLOAD" }),
    ]));
  });

  it("promotes a real decoded QR URL in verified malicious intelligence to Confirmed Threat and auto-trash eligibility", () => {
    const links = decodedQrLinks();
    const result = scanMessage(baseEnvelope("gmail", links), {
      personalPolicy: new InMemoryPersonalPolicyStore(),
      threatFeed: confirmedUrlFeed(QR_URL),
    });

    expect(result.scored.verdict).toBe("confirmed_threat");
    expect(result.scored.confirmedByRule).toBe(true);
    expect(result.action).toBe("auto_trash_allowed");
    expect(result.scored.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ layer: "global_intelligence", code: "GLOBAL_CONFIRMED_MATCH", source: "signed_feed" }),
    ]));
  });

  it.each<Provider>(["gmail", "outlook", "icloud", "yahoo", "imap"])(
    "preserves QR threat semantics across %s normalization",
    (provider) => {
      const result = scanMessage(baseEnvelope(provider, decodedQrLinks()), {
        personalPolicy: new InMemoryPersonalPolicyStore(),
        threatFeed: confirmedUrlFeed(QR_URL),
      });
      expect(result.scored.verdict).toBe("confirmed_threat");
      expect(result.action).toBe("auto_trash_allowed");
    },
  );

  it("shows that hiding the same suspicious HTTPS destination in QR increases risk without inventing a confirmed-malicious verdict", () => {
    const link: LinkInfo = {
      visibleText: QR_URL,
      rawUrl: QR_URL,
      normalizedUrl: QR_URL,
      claimedBrand: null,
      brandDomainMismatch: null,
      source: "body",
    };
    const visible = scanMessage(baseEnvelope("gmail", [link]), {
      personalPolicy: new InMemoryPersonalPolicyStore(),
      threatFeed: emptyFeed,
    });
    const hiddenInQr = scanMessage(baseEnvelope("gmail", decodedQrLinks()), {
      personalPolicy: new InMemoryPersonalPolicyStore(),
      threatFeed: emptyFeed,
    });

    expect(visible.scored.evidence.some((item) => item.code === "LINK_EMBEDDED_IN_QR" || item.code === "QR_CODE_URL_PAYLOAD")).toBe(false);
    expect(visible.scored.verdict).toBe("review");
    expect(visible.scored.confirmedByRule).toBe(false);
    expect(hiddenInQr.scored.verdict).toBe("high_risk");
    expect(hiddenInQr.scored.confirmedByRule).toBe(false);
  });

  it("marks bounded QR inspection overflow incomplete so adapters can never treat uninspected supported images as fully covered", () => {
    const analysis = analyzeQrImages(Array.from({ length: 5 }, (_, index) => ({
      name: `qr-${index}.png`, mimeType: "image/png", content: URL_QR_PNG,
    })));
    expect(analysis.results).toHaveLength(4);
    expect(analysis.links).toHaveLength(4);
    expect(analysis.incomplete).toBe(true);
    expect(analysis.incompleteReasons.join(" ")).toContain("first 4 supported images");
  });
});
