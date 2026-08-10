import { describe, expect, it } from "vitest";
import type { CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import {
  organizationalDomain,
  sameOrganizationalDomain,
} from "../../server/src/util/domainRelation.js";
import {
  alignedAuthenticationDomains,
  authenticationPassed,
} from "../../server/src/engine/identitySignals.js";
import { linkStructureLayer } from "../../server/src/engine/layers/linkStructure.js";

function envelope(overrides: Partial<CanonicalEnvelope> = {}): CanonicalEnvelope {
  return {
    provider: "gmail",
    accountProof: "proof",
    messageId: "message-id",
    providerNativeId: "native-id",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: {
      displayName: "Northwind School",
      address: "security@alerts.northwind.pvt.k12.ma.us",
      domain: "alerts.northwind.pvt.k12.ma.us",
    },
    replyTo: null,
    subject: "Account information",
    date: new Date(0).toISOString(),
    authentication: { providerTrust: "trusted",
      spf: "pass",
      dkim: "unknown",
      dmarc: "none",
      arc: "none",
      rawHeader: "mx.receiver.example; spf=pass smtp.mailfrom=bounce@mailer.northwind.pvt.k12.ma.us",
    },
    textPreview: "Routine account information from the sender. ".repeat(4),
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

describe("Public Suffix List registrable-domain boundary", () => {
  it("preserves ordinary registrable domains and their subdomains", () => {
    expect(organizationalDomain("mail.example.com")).toBe("example.com");
    expect(organizationalDomain("login.example.co.uk")).toBe("example.co.uk");
    expect(sameOrganizationalDomain("mail.example.co.uk", "login.example.co.uk")).toBe(true);
  });

  it("does not collapse distinct registrants beneath a deep public suffix", () => {
    expect(organizationalDomain("mail.northwind.pvt.k12.ma.us")).toBe("northwind.pvt.k12.ma.us");
    expect(organizationalDomain("mail.contoso.pvt.k12.ma.us")).toBe("contoso.pvt.k12.ma.us");
    expect(sameOrganizationalDomain(
      "mail.northwind.pvt.k12.ma.us",
      "mail.contoso.pvt.k12.ma.us",
    )).toBe(false);
  });

  it("honors wildcard and exception rules instead of fixed label counts", () => {
    expect(organizationalDomain("account.alpha.ck")).toBe("account.alpha.ck");
    expect(organizationalDomain("login.alpha.ck")).toBe("login.alpha.ck");
    expect(sameOrganizationalDomain("account.alpha.ck", "login.alpha.ck")).toBe(false);
    expect(organizationalDomain("portal.www.ck")).toBe("www.ck");
    expect(sameOrganizationalDomain("portal.www.ck", "login.www.ck")).toBe(true);
  });

  it("treats private multi-tenant suffixes as tenant boundaries", () => {
    expect(organizationalDomain("assets.alice.github.io")).toBe("alice.github.io");
    expect(organizationalDomain("login.bob.github.io")).toBe("bob.github.io");
    expect(sameOrganizationalDomain("assets.alice.github.io", "login.bob.github.io")).toBe(false);
  });

  it("does not invent an owner for a bare public suffix", () => {
    expect(organizationalDomain("co.uk")).toBe("");
    expect(sameOrganizationalDomain("co.uk", "co.uk")).toBe(false);
  });

  it("keeps IP and single-label compatibility without treating them as cross-domain matches", () => {
    expect(organizationalDomain("127.0.0.1")).toBe("127.0.0.1");
    expect(organizationalDomain("localhost")).toBe("localhost");
    expect(sameOrganizationalDomain("localhost", "internal")).toBe(false);
  });
});

describe("PSL-backed authentication alignment", () => {
  it("rejects an SPF pass from a different registrant under the same deep public suffix", () => {
    const message = envelope({
      authentication: { providerTrust: "trusted",
        spf: "pass",
        dkim: "unknown",
        dmarc: "none",
        arc: "none",
        rawHeader: "mx.receiver.example; spf=pass smtp.mailfrom=bounce@mailer.attacker.pvt.k12.ma.us",
      },
    });

    expect(authenticationPassed(message)).toBe(false);
    expect(alignedAuthenticationDomains(message)).toEqual([]);
  });

  it("accepts a real sibling subdomain inside the same registrable organization", () => {
    const message = envelope();
    expect(authenticationPassed(message)).toBe(true);
    expect(alignedAuthenticationDomains(message)).toEqual(["northwind.pvt.k12.ma.us"]);
  });

  it("does not align different private-suffix tenants", () => {
    const message = envelope({
      from: {
        displayName: "Alice Pages",
        address: "security@alice.github.io",
        domain: "alice.github.io",
      },
      authentication: { providerTrust: "trusted",
        spf: "unknown",
        dkim: "pass",
        dmarc: "none",
        arc: "none",
        rawHeader: "mx.receiver.example; dkim=pass header.d=bob.github.io header.s=s1",
      },
    });

    expect(authenticationPassed(message)).toBe(false);
  });
});

describe("PSL-backed link identity boundaries", () => {
  it("detects displayed-vs-actual deception between deep-suffix registrants", () => {
    const message = envelope({
      authentication: { providerTrust: "trusted", spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
      links: [{
        visibleText: "https://login.northwind.pvt.k12.ma.us",
        rawUrl: "https://login.attacker.pvt.k12.ma.us/verify",
        normalizedUrl: "https://login.attacker.pvt.k12.ma.us/verify",
        claimedBrand: null,
        brandDomainMismatch: null,
        source: "body",
        interaction: "navigation",
      }],
    });

    const result = linkStructureLayer(message);
    expect(result.evidence).toContainEqual(expect.objectContaining({
      code: "DISPLAYED_VS_ACTUAL_MISMATCH",
      scoreContribution: 4,
    }));
  });

  it("treats a sensitive action into another private-suffix tenant as cross-domain", () => {
    const message = envelope({
      from: {
        displayName: "Alice Pages",
        address: "security@alice.github.io",
        domain: "alice.github.io",
      },
      authentication: { providerTrust: "trusted", spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
      links: [{
        visibleText: "Sign in to your account",
        rawUrl: "https://bob.github.io/login",
        normalizedUrl: "https://bob.github.io/login",
        claimedBrand: null,
        brandDomainMismatch: null,
        source: "body",
        interaction: "navigation",
      }],
    });

    const result = linkStructureLayer(message);
    expect(result.evidence).toContainEqual(expect.objectContaining({
      code: "SENSITIVE_ACTION_CROSS_DOMAIN",
      scoreContribution: 2,
    }));
  });
});
