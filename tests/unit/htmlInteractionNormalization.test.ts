import { describe, expect, it } from "vitest";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";
import { buildCommunityReportContext } from "../../server/src/community/fingerprint.js";
import { MAX_HTML_INTERACTION_CHARS } from "../../server/src/util/htmlInteraction.js";
import { normalizeRawMessage } from "../../server/src/util/mimeNormalize.js";

const emptyDeps = {
  personalPolicy: new InMemoryPersonalPolicyStore(),
  threatFeed: { getVerifiedEntries: () => [] },
};

function rawHtml(html: string, options: { from?: string; subject?: string; auth?: string } = {}): string {
  return [
    `From: ${options.from ?? "Sender <sender@example.com>"}`,
    "To: user@example.test",
    `Subject: ${options.subject ?? "HTML interaction test"}`,
    "Message-ID: <html-interaction@example.test>",
    "Date: Mon, 10 Aug 2026 10:00:00 +0000",
    ...(options.auth ? [`Authentication-Results: ${options.auth}`] : []),
    "MIME-Version: 1.0",
    "Content-Type: text/html; charset=utf-8",
    "",
    html,
  ].join("\r\n");
}

async function normalize(raw: string) {
  return normalizeRawMessage(raw, {
    provider: "gmail",
    accountProof: "fixture-proof",
    providerFolderName: "INBOX",
    normalizedFolder: "inbox",
    providerNativeId: "html-native",
  });
}

function evidenceCodes(result: ReturnType<typeof scanMessage>): string[] {
  return result.scored.evidence.map((item) => item.code);
}

describe("bounded HTML interaction normalization", () => {
  it("extracts an unquoted href and exposes displayed-versus-actual deception", async () => {
    const envelope = await normalize(rawHtml(
      '<p>Review your account.</p><a href=https://evil.example/login>https://bank.example</a>',
    ));

    expect(envelope.links).toEqual(expect.arrayContaining([
      expect.objectContaining({
        rawUrl: "https://evil.example/login",
        normalizedUrl: "https://evil.example/login",
        visibleText: "https://bank.example",
        interaction: "navigation",
      }),
    ]));
    expect(evidenceCodes(scanMessage(envelope, emptyDeps))).toContain("DISPLAYED_VS_ACTUAL_MISMATCH");
  });

  it("decodes entity-obfuscated destination and visible-domain text before structural analysis", async () => {
    const envelope = await normalize(rawHtml(
      '<a href="https&#58;&#47;&#47;evil.example/login?x=1&amp;y=2">https://secure&#46;bank.example</a>',
    ));
    const link = envelope.links.find((item) => item.source === "body");

    expect(link?.normalizedUrl).toBe("https://evil.example/login?x=1&y=2");
    expect(link?.visibleText).toBe("https://secure.bank.example");
    expect(evidenceCodes(scanMessage(envelope, emptyDeps))).toContain("DISPLAYED_VS_ACTUAL_MISMATCH");
  });

  it("resolves relative navigation against a bounded trusted HTTP(S) BASE element", async () => {
    const envelope = await normalize(rawHtml(
      '<base href=https://evil.example/root/><a href=login>Sign in</a>',
    ));

    expect(envelope.links).toEqual(expect.arrayContaining([
      expect.objectContaining({
        rawUrl: "login",
        normalizedUrl: "https://evil.example/root/login",
        interaction: "navigation",
      }),
    ]));
  });

  it("keeps a URL from the text alternative even when an HTML alternative exists", async () => {
    const boundary = "interaction-boundary";
    const raw = [
      "From: Sender <sender@example.com>",
      "To: user@example.test",
      "Subject: Multipart destination",
      "Message-ID: <multipart-interaction@example.test>",
      "Date: Mon, 10 Aug 2026 10:00:00 +0000",
      "MIME-Version: 1.0",
      `Content-Type: multipart/alternative; boundary=${boundary}`,
      "",
      `--${boundary}`,
      "Content-Type: text/plain; charset=utf-8",
      "",
      "Open https://text-only-destination.example/login to continue.",
      `--${boundary}`,
      "Content-Type: text/html; charset=utf-8",
      "",
      "<p>Open the account notice to continue.</p>",
      `--${boundary}--`,
      "",
    ].join("\r\n");

    const envelope = await normalize(raw);
    expect(envelope.htmlSignals).not.toBeNull();
    expect(envelope.links.map((link) => link.normalizedUrl)).toContain("https://text-only-destination.example/login");
  });

  it("turns an unquoted password-form action into canonical link and structural evidence", async () => {
    const envelope = await normalize(rawHtml(
      '<form action=https://credential.example/submit><input name=user><input TYPE=password></form>',
      {
        from: "Account Service <security@service.example>",
        auth: "mx.local; spf=pass; dkim=pass; dmarc=pass",
      },
    ));
    // This regression is about HTML/link behavior, not Authentication-Results
    // provenance. The synthetic receiver result is therefore trusted explicitly.
    envelope.authentication.providerTrust = "trusted";
    const result = scanMessage(envelope, emptyDeps);

    expect(envelope.htmlSignals).toMatchObject({ hasForm: true, hasPasswordField: true });
    expect(envelope.links).toEqual(expect.arrayContaining([
      expect.objectContaining({
        normalizedUrl: "https://credential.example/submit",
        interaction: "form_action",
      }),
    ]));
    expect(evidenceCodes(result)).toContain("EMBEDDED_PASSWORD_FORM");
    expect(evidenceCodes(result)).toContain("SENSITIVE_ACTION_CROSS_DOMAIN");
    expect(result.scored.verdict).toBe("review");
  });

  it("feeds form-action domains into signed intelligence and only domain-reduced community reporting", async () => {
    const envelope = await normalize(rawHtml(
      '<form action="https://credential.example/private/login?token=secret"><input type=password></form>',
    ));
    const result = scanMessage(envelope, {
      personalPolicy: new InMemoryPersonalPolicyStore(),
      threatFeed: {
        getVerifiedEntries: () => [{
          type: "url_domain" as const,
          value: "credential.example",
          confirmedThreat: true,
          ruleId: "html-form-domain",
        }],
      },
    });
    const report = buildCommunityReportContext(envelope, result.scored);
    const serialized = JSON.stringify(report);

    expect(result.scored.verdict).toBe("confirmed_threat");
    expect(report.indicators).toContainEqual({ type: "url_domain", value: "credential.example" });
    expect(serialized).not.toContain("/private/login");
    expect(serialized).not.toContain("token=secret");
  });

  it("extracts META refresh as an automatic destination without executing it", async () => {
    const envelope = await normalize(rawHtml(
      '<meta http-equiv=refresh content="0;url=https://redirect.example/landing"><p>Notice</p>',
    ));
    const result = scanMessage(envelope, emptyDeps);

    expect(envelope.links).toEqual(expect.arrayContaining([
      expect.objectContaining({
        normalizedUrl: "https://redirect.example/landing",
        interaction: "automatic_redirect",
      }),
    ]));
    expect(evidenceCodes(result)).toContain("AUTOMATIC_HTML_REDIRECT");
  });

  it("keeps unsafe schemes visible when they are carried by unquoted HTML attributes", async () => {
    const envelope = await normalize(rawHtml('<a href=javascript:alert(1)>Open</a>'));
    expect(evidenceCodes(scanMessage(envelope, emptyDeps))).toContain("UNSAFE_LINK_SCHEME");
  });

  it("blocks an automatic Safe verdict when attacker-controlled HTML exceeds the inspection bound", async () => {
    const padding = "A".repeat(MAX_HTML_INTERACTION_CHARS + 128);
    const envelope = await normalize(rawHtml(`<p>${padding}</p><a href=https://hidden-after-limit.example>Continue</a>`, {
      from: "Trusted Service <notice@trusted.example>",
      auth: "mx.local; spf=pass; dkim=pass; dmarc=pass",
    }));
    const result = scanMessage(envelope, emptyDeps);

    expect(envelope.parseStatus).toBe("partial");
    expect(envelope.diagnostics.contentCoverage).toBe("insufficient");
    expect(envelope.parseNotes).toContain(`HTML interaction inspection was bounded to ${MAX_HTML_INTERACTION_CHARS} characters.`);
    expect(envelope.links.map((link) => link.normalizedUrl)).not.toContain("https://hidden-after-limit.example/");
    expect(result.scored.verdict).not.toBe("safe");
  });

  it("keeps ordinary authenticated same-organization HTML free of new interaction warnings", async () => {
    const envelope = await normalize(rawHtml(
      '<p>Your monthly account summary is ready.</p><a href="https://portal.service.example/summary">View summary</a>',
      {
        from: "Service <news@service.example>",
        auth: "mx.local; spf=pass; dkim=pass; dmarc=pass",
      },
    ));
    const codes = evidenceCodes(scanMessage(envelope, emptyDeps));

    expect(codes).not.toContain("EMBEDDED_PASSWORD_FORM");
    expect(codes).not.toContain("AUTOMATIC_HTML_REDIRECT");
    expect(codes).not.toContain("SENSITIVE_ACTION_CROSS_DOMAIN");
  });
});
