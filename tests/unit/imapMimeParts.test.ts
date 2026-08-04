import { describe, expect, it } from "vitest";
import {
  buildSyntheticRawMessage,
  decodeTextBuffer,
  inspectBodyStructure,
} from "../../server/src/adapters/imap/mimeParts.js";
import { normalizeRawMessage } from "../../server/src/util/mimeNormalize.js";

describe("IMAP MIME part selection", () => {
  it("selects readable alternatives and records attachment metadata without content", () => {
    const result = inspectBodyStructure({
      type: "multipart/mixed",
      childNodes: [
        {
          part: "1",
          type: "multipart/alternative",
          childNodes: [
            { part: "1.1", type: "text/plain", size: 420 },
            { part: "1.2", type: "text/html", size: 900 },
          ],
        },
        {
          part: "2",
          type: "application/pdf",
          size: 123456,
          disposition: "attachment",
          dispositionParameters: { filename: "invoice.pdf.exe" },
        },
      ],
    });

    expect(result.plainPart).toBe("1.1");
    expect(result.htmlPart).toBe("1.2");
    expect(result.attachments).toEqual([
      expect.objectContaining({
        name: "invoice.pdf.exe",
        mimeType: "application/pdf",
        sizeBytes: 123456,
        extension: "exe",
        suspiciousNamePattern: true,
        sha256: null,
      }),
    ]);
  });

  it("does not treat an inline image as a downloadable attachment", () => {
    const result = inspectBodyStructure({
      type: "multipart/related",
      childNodes: [
        { part: "1", type: "text/html", size: 1000 },
        { part: "2", type: "image/png", size: 2000, disposition: "inline" },
      ],
    });

    expect(result.htmlPart).toBe("1");
    expect(result.attachments).toEqual([]);
  });

  it("rebuilds a bounded readable message without retaining multipart headers", async () => {
    const raw = buildSyntheticRawMessage({
      headers: Buffer.from([
        "From: PayPal Security <billing@unrelated.example>",
        "Subject: PayPal payment received - Bitcoin order processing",
        "Authentication-Results: mx.local; spf=fail; dkim=fail; dmarc=fail",
        "Content-Type: multipart/mixed; boundary=old-boundary",
        "Content-Transfer-Encoding: base64",
        "MIME-Version: 1.0",
        "",
      ].join("\r\n")),
      body: "A payment of $750 for Bitcoin is processing. If this was not you, call +1 555 0100 now.",
      contentType: "text/plain",
    });

    const text = raw.toString("utf8");
    expect(text).not.toContain("old-boundary");
    expect(text).toContain("Content-Type: text/plain; charset=utf-8");

    const envelope = await normalizeRawMessage(raw, {
      provider: "icloud",
      accountProof: "proof",
      providerFolderName: "Junk",
      normalizedFolder: "spam",
      providerNativeId: "native",
    });

    expect(envelope.subject).toContain("PayPal payment received");
    expect(envelope.textPreview).toContain("$750");
    expect(envelope.authentication).toMatchObject({ spf: "fail", dkim: "fail", dmarc: "fail" });
    expect(envelope.parseStatus).toBe("complete");
  });

  it("decodes supported provider charsets and safely falls back", () => {
    expect(decodeTextBuffer(Buffer.from("hello", "utf8"), "utf-8")).toBe("hello");
    expect(decodeTextBuffer(Buffer.from("hello", "utf8"), "not-a-real-charset")).toBe("hello");
  });
});
