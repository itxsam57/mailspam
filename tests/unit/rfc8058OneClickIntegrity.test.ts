import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { normalizeRawMessage } from "../../server/src/util/mimeNormalize.js";
import { extractOneClickDkimSignatures } from "../../server/src/util/rfc8058Metadata.js";
import { trustedPassingDkimIdentities } from "../../server/src/engine/identitySignals.js";
import { unsubscribeCapability } from "../../server/src/workflows/unsubscribe.js";

const opts = {
  provider: "gmail" as const,
  accountProof: "fixture-proof",
  providerFolderName: "INBOX",
  normalizedFolder: "inbox" as const,
  providerNativeId: "rfc8058-test",
};

function rawMessage(options: {
  auth?: string;
  dkim?: string[];
  list?: string;
  post?: string;
} = {}): string {
  const auth = options.auth ?? "mx.receiver.example; dkim=pass header.d=mailer.example.test header.s=mail2026";
  const signatures = options.dkim ?? [
    "v=1; a=rsa-sha256; d=mailer.example.test; s=mail2026; h=From:To:Subject:List-Unsubscribe:List-Unsubscribe-Post; bh=dummy; b=dummy",
  ];
  return [
    "From: Example List <news@example.test>",
    "To: user@example.test",
    "Subject: Weekly update",
    "Message-ID: <rfc8058@example.test>",
    "Date: Mon, 10 Aug 2026 10:00:00 +0000",
    `Authentication-Results: ${auth}`,
    ...signatures.map((value) => `DKIM-Signature: ${value}`),
    `List-Unsubscribe: ${options.list ?? "<https://example.test/unsubscribe?id=123>"}`,
    `List-Unsubscribe-Post: ${options.post ?? "List-Unsubscribe=One-Click"}`,
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Routine newsletter body.",
  ].join("\r\n");
}

async function normalized(raw: string, trusted = true) {
  const envelope = await normalizeRawMessage(raw, opts);
  envelope.authentication.providerTrust = trusted ? "trusted" : "unknown";
  return envelope;
}

describe("RFC 8058 one-click authorization integrity", () => {
  it("offers one-click only for a trusted passing DKIM identity whose exact signature covers both list headers", async () => {
    const envelope = await normalized(rawMessage());

    expect(envelope.listHeaders.oneClickHeaderSetUnambiguous).toBe(true);
    expect(envelope.listHeaders.oneClickDkimSignatures).toEqual([
      { domain: "mailer.example.test", selector: "mail2026", coversRequiredHeaders: true },
    ]);
    expect(trustedPassingDkimIdentities(envelope)).toEqual([
      { domain: "mailer.example.test", selector: "mail2026" },
    ]);
    expect(unsubscribeCapability(envelope)).toEqual({
      available: true,
      method: "one_click_post",
      target: "https://example.test/unsubscribe?id=123",
      source: "list_header",
    });
  });

  it("refuses browser GET when List-Unsubscribe-Post is not covered by DKIM", async () => {
    const envelope = await normalized(rawMessage({
      dkim: ["v=1; d=mailer.example.test; s=mail2026; h=From:To:Subject:List-Unsubscribe; bh=x; b=y"],
    }));

    expect(envelope.listHeaders.oneClickDkimSignatures).toEqual([
      { domain: "mailer.example.test", selector: "mail2026", coversRequiredHeaders: false },
    ]);
    expect(unsubscribeCapability(envelope).method).toBe("none");
  });

  it("refuses browser GET when List-Unsubscribe itself is not covered by DKIM", async () => {
    const envelope = await normalized(rawMessage({
      dkim: ["v=1; d=mailer.example.test; s=mail2026; h=From:To:Subject:List-Unsubscribe-Post; bh=x; b=y"],
    }));
    expect(unsubscribeCapability(envelope).method).toBe("none");
  });

  it("refuses browser GET when Authentication-Results provenance is not trusted", async () => {
    const envelope = await normalized(rawMessage(), false);
    expect(trustedPassingDkimIdentities(envelope)).toEqual([]);
    expect(unsubscribeCapability(envelope).method).toBe("none");
  });

  it("refuses browser GET when the passing DKIM domain does not match the raw signature", async () => {
    const envelope = await normalized(rawMessage({
      auth: "mx.receiver.example; dkim=pass header.d=other.example.test header.s=mail2026",
    }));
    expect(unsubscribeCapability(envelope).method).toBe("none");
  });

  it("refuses browser GET when trusted DKIM pass omits header.s", async () => {
    const envelope = await normalized(rawMessage({
      auth: "mx.receiver.example; dkim=pass header.d=mailer.example.test",
    }));
    expect(trustedPassingDkimIdentities(envelope)).toEqual([]);
    expect(unsubscribeCapability(envelope).method).toBe("none");
  });

  it("fails closed on ambiguous duplicate covering signatures for the same domain and selector", async () => {
    const signature = "v=1; d=mailer.example.test; s=mail2026; h=From:List-Unsubscribe:List-Unsubscribe-Post; bh=x; b=y";
    const envelope = await normalized(rawMessage({ dkim: [signature, signature] }));

    expect(envelope.listHeaders.oneClickDkimSignatures).toHaveLength(2);
    expect(unsubscribeCapability(envelope).method).toBe("none");
  });

  it("fails closed when one same-identity signature covers the headers and another does not", async () => {
    const covering = "v=1; d=mailer.example.test; s=mail2026; h=From:List-Unsubscribe:List-Unsubscribe-Post; bh=x; b=covered";
    const nonCovering = "v=1; d=mailer.example.test; s=mail2026; h=From:Subject; bh=x; b=other";
    const envelope = await normalized(rawMessage({ dkim: [covering, nonCovering] }));

    expect(envelope.listHeaders.oneClickDkimSignatures).toEqual([
      { domain: "mailer.example.test", selector: "mail2026", coversRequiredHeaders: true },
      { domain: "mailer.example.test", selector: "mail2026", coversRequiredHeaders: false },
    ]);
    expect(unsubscribeCapability(envelope).method).toBe("none");
  });

  it("does not let ARC pass substitute for a trusted DKIM pass", async () => {
    const envelope = await normalized(rawMessage({
      auth: "mx.receiver.example; arc=pass; dkim=fail header.d=mailer.example.test header.s=mail2026",
    }));
    expect(unsubscribeCapability(envelope).method).toBe("none");
  });

  it("preserves a mailto plus HTTPS List-Unsubscribe and selects HTTPS only when one-click is authorized", async () => {
    const envelope = await normalized(rawMessage({
      list: "<mailto:unsubscribe@example.test?subject=unsubscribe>, <https://example.test/unsubscribe?id=123>",
    }));
    const capability = unsubscribeCapability(envelope);

    expect(envelope.listHeaders.listUnsubscribe).toContain("mailto:unsubscribe@example.test");
    expect(envelope.listHeaders.listUnsubscribe).toContain("https://example.test/unsubscribe?id=123");
    expect(envelope.listHeaders.oneClickHeaderSetUnambiguous).toBe(true);
    expect(capability.method).toBe("one_click_post");
    expect(capability.target).toBe("https://example.test/unsubscribe?id=123");
  });

  it("preserves manual targets but refuses automatic one-click when raw list headers are duplicated", async () => {
    const raw = rawMessage().replace(
      "List-Unsubscribe: <https://example.test/unsubscribe?id=123>",
      "List-Unsubscribe: <mailto:unsubscribe@example.test>\r\nList-Unsubscribe: <https://example.test/unsubscribe?id=123>",
    );
    const envelope = await normalized(raw);

    expect(envelope.listHeaders.listUnsubscribe).toContain("mailto:unsubscribe@example.test");
    expect(envelope.listHeaders.listUnsubscribe).toContain("https://example.test/unsubscribe?id=123");
    expect(envelope.listHeaders.oneClickHeaderSetUnambiguous).toBe(false);
    expect(unsubscribeCapability(envelope)).toMatchObject({
      method: "mailto",
      target: "mailto:unsubscribe@example.test",
      source: "list_header",
    });
  });

  it("retains only bounded domain/selector/coverage metadata, never signature values or the full h list", () => {
    const raw = rawMessage({
      dkim: ["v=1; d=mailer.example.test; s=mail2026; h=From:To:Subject:List-Unsubscribe:List-Unsubscribe-Post:X-Private-Header; bh=verysecretbodyhash; b=verysecretsignature"],
    });
    const metadata = extractOneClickDkimSignatures(raw);
    const serialized = JSON.stringify(metadata);

    expect(metadata).toEqual([{ domain: "mailer.example.test", selector: "mail2026", coversRequiredHeaders: true }]);
    expect(serialized).not.toContain("verysecret");
    expect(serialized).not.toContain("X-Private-Header");
    expect(serialized).not.toContain("bh=");
    expect(serialized).not.toContain("b=");
  });

  it("fails closed when the raw header section exceeds the parser bound before termination", () => {
    const oversized = [
      "From: Example <news@example.test>",
      `X-Padding: ${"A".repeat(140 * 1024)}`,
      "DKIM-Signature: v=1; d=mailer.example.test; s=mail2026; h=List-Unsubscribe:List-Unsubscribe-Post; b=x",
      "",
      "body",
    ].join("\r\n");
    expect(extractOneClickDkimSignatures(oversized)).toEqual([]);
  });

  it("does not expose internal DKIM correlation metadata when the API strips list action headers for browser output", () => {
    const serverSource = readFileSync(join(import.meta.dirname, "../../server/src/api/server.ts"), "utf8");
    expect(serverSource).toContain("result.envelope.listHeaders = {");
    expect(serverSource).toContain("listUnsubscribe: null");
    expect(serverSource).toContain("listUnsubscribePost: null");
    expect(serverSource).not.toMatch(/result\.envelope\.listHeaders\s*=\s*\{[^}]*oneClickDkimSignatures/s);
    expect(serverSource).not.toMatch(/result\.envelope\.listHeaders\s*=\s*\{[^}]*oneClickHeaderSetUnambiguous/s);
  });

  it("keeps the existing browser confirmation requirement before a one-click request is sent", () => {
    const browserSource = readFileSync(join(import.meta.dirname, "../../web/unsubscribe-monitor.js"), "utf8");
    const confirmIndex = browserSource.indexOf("window.confirm(");
    const requestIndex = browserSource.indexOf("/messages/unsubscribe");
    expect(confirmIndex).toBeGreaterThan(-1);
    expect(requestIndex).toBeGreaterThan(confirmIndex);
  });
});
