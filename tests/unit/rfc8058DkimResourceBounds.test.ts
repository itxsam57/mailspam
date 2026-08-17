import { describe, expect, it } from "vitest";
import { extractOneClickDkimSignatures } from "../../server/src/util/rfc8058Metadata.js";
import { normalizeRawMessage } from "../../server/src/util/mimeNormalize.js";
import { unsubscribeCapability } from "../../server/src/workflows/unsubscribe.js";

function baseHeaders(signatures: string[]): string {
  return [
    "From: Example List <news@example.test>",
    "To: user@example.test",
    "Subject: Weekly update",
    "Message-ID: <rfc8058-resource@example.test>",
    "Date: Mon, 10 Aug 2026 10:00:00 +0000",
    "Authentication-Results: mx.receiver.example; dkim=pass header.d=mailer.example.test header.s=mail2026",
    ...signatures.map((value) => `DKIM-Signature: ${value}`),
    "List-Unsubscribe: <https://example.test/unsubscribe>",
    "List-Unsubscribe-Post: List-Unsubscribe=One-Click",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Routine newsletter body.",
  ].join("\r\n");
}

const covering = "v=1; d=mailer.example.test; s=mail2026; h=From:List-Unsubscribe:List-Unsubscribe-Post; bh=x; b=y";

describe("RFC 8058 DKIM inspection resource bounds", () => {
  it("rejects the whole one-click signature set when the signature-count cap is exceeded", async () => {
    const raw = baseHeaders(Array.from({ length: 17 }, () => covering));
    expect(extractOneClickDkimSignatures(raw)).toEqual([]);

    const envelope = await normalizeRawMessage(raw, {
      provider: "gmail",
      accountProof: "fixture-proof",
      providerFolderName: "INBOX",
      normalizedFolder: "inbox",
      providerNativeId: "rfc8058-many-signatures",
    });
    envelope.authentication.providerTrust = "trusted";
    expect(unsubscribeCapability(envelope).method).toBe("none");
  });

  it("rejects the whole one-click signature set when any DKIM signature exceeds its inspection bound", async () => {
    const oversized = `v=1; d=other.example.test; s=other; h=From; b=${"A".repeat(17 * 1024)}`;
    const raw = baseHeaders([covering, oversized]);
    expect(extractOneClickDkimSignatures(raw)).toEqual([]);

    const envelope = await normalizeRawMessage(raw, {
      provider: "gmail",
      accountProof: "fixture-proof",
      providerFolderName: "INBOX",
      normalizedFolder: "inbox",
      providerNativeId: "rfc8058-oversized-signature",
    });
    envelope.authentication.providerTrust = "trusted";
    expect(unsubscribeCapability(envelope).method).toBe("none");
  });
});
