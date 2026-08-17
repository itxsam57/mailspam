import { describe, expect, it } from "vitest";
import { normalizeRawMessage } from "../../server/src/util/mimeNormalize.js";
import { unsubscribeCapability } from "../../server/src/workflows/unsubscribe.js";

const opts = {
  provider: "gmail" as const,
  accountProof: "fixture-proof",
  providerFolderName: "INBOX",
  normalizedFolder: "inbox" as const,
  providerNativeId: "ema6-rfc8058-boundary",
};

function rawMessage(list: string, post: string | null): string {
  return [
    "From: Example List <news@example.test>",
    "To: user@example.test",
    "Subject: Weekly update",
    "Message-ID: <ema6@example.test>",
    "Date: Mon, 10 Aug 2026 10:00:00 +0000",
    "Authentication-Results: mx.receiver.example; dkim=fail header.d=mailer.example.test header.s=mail2026",
    "DKIM-Signature: v=1; a=rsa-sha256; d=mailer.example.test; s=mail2026; h=From:To:Subject:List-Unsubscribe:List-Unsubscribe-Post; bh=dummy; b=dummy",
    `List-Unsubscribe: ${list}`,
    ...(post ? [`List-Unsubscribe-Post: ${post}`] : []),
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Routine newsletter body.",
  ].join("\r\n");
}

async function capability(list: string, post: string | null) {
  const envelope = await normalizeRawMessage(rawMessage(list, post), opts);
  envelope.authentication.providerTrust = "trusted";
  return unsubscribeCapability(envelope);
}

describe("EMA-6 RFC 8058 manual fallback boundary", () => {
  it("never reinterprets an unauthorized one-click HTTPS POST endpoint as a browser GET link", async () => {
    const result = await capability(
      "<https://unsubscribe.example.test/u/opaque>",
      "List-Unsubscribe=One-Click",
    );

    expect(result).toMatchObject({
      available: false,
      method: "none",
      target: null,
      source: "none",
    });
  });

  it("uses an independent mailto fallback instead of opening the declared one-click POST URL with GET", async () => {
    const result = await capability(
      "<mailto:leave@example.com>, <https://unsubscribe.example.test/u/opaque>",
      "List-Unsubscribe=One-Click",
    );

    expect(result).toMatchObject({
      available: true,
      method: "mailto",
      target: "mailto:leave@example.com",
      source: "list_header",
    });
  });

  it("keeps ordinary non-one-click HTTPS List-Unsubscribe links available for manual browser use", async () => {
    const result = await capability("<https://example.test/preferences>", null);

    expect(result).toMatchObject({
      available: true,
      method: "link_only",
      target: "https://example.test/preferences",
      source: "list_header",
    });
  });
});
