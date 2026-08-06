import { describe, expect, it, vi } from "vitest";
import {
  boundedTextPartWasTruncated,
  buildSyntheticRawMessage,
  buildSyntheticReadableMessage,
  decodeFetchedTextPart,
  decodeTextBuffer,
  inspectBodyStructure,
} from "../../server/src/adapters/imap/mimeParts.js";
import { fetchBoundedReadableBodies } from "../../server/src/adapters/imap/imapAdapter.js";
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
            { part: "1.1", type: "text/plain", size: 420, encoding: "quoted-printable", parameters: { charset: "utf-8" } },
            { part: "1.2", type: "text/html", size: 900, encoding: "base64", parameters: { charset: "utf-8" } },
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
    expect(result.plain).toMatchObject({
      part: "1.1",
      contentType: "text/plain",
      sizeBytes: 420,
      charset: "utf-8",
      transferEncoding: "quoted-printable",
    });
    expect(result.html).toMatchObject({
      part: "1.2",
      contentType: "text/html",
      sizeBytes: 900,
      charset: "utf-8",
      transferEncoding: "base64",
    });
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

  it("addresses a single-part root body as TEXT without an extra part lookup", () => {
    const result = inspectBodyStructure({
      type: "text/plain",
      size: 120,
      encoding: "7bit",
      parameters: { charset: "utf-8" },
    });

    expect(result.plainPart).toBe("TEXT");
    expect(result.plain).toMatchObject({ part: "TEXT", contentType: "text/plain", sizeBytes: 120 });
  });

  it("does not select readable descendants of an attached message as the main body", () => {
    const result = inspectBodyStructure({
      type: "multipart/mixed",
      childNodes: [
        { part: "1", type: "text/plain", size: 200 },
        {
          part: "2",
          type: "message/rfc822",
          disposition: "attachment",
          childNodes: [{ part: "2.1", type: "text/html", size: 5000 }],
        },
      ],
    });

    expect(result.plainPart).toBe("1");
    expect(result.htmlPart).toBeNull();
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

  it("preserves both plain text and HTML destinations in the bounded synthetic message", async () => {
    const raw = buildSyntheticReadableMessage({
      headers: "From: Sender <sender@example.com>\r\nSubject: Verify account\r\n",
      plainBody: "Review your account notification.",
      htmlBody: '<p>Review your account notification.</p><a href="https://evil.example/login">Continue</a>',
    });
    const envelope = await normalizeRawMessage(raw, {
      provider: "icloud",
      accountProof: "proof",
      providerFolderName: "INBOX",
      normalizedFolder: "inbox",
      providerNativeId: "native-2",
    });

    expect(envelope.textPreview).toContain("Review your account");
    expect(envelope.htmlSignals?.extractedText).toContain("Continue");
    expect(envelope.links.map((link) => link.normalizedUrl)).toContain("https://evil.example/login");
  });

  it("decodes bounded base64 and quoted-printable alternatives in one provider fetch", async () => {
    const plainText = "This account notice contains readable plain text.";
    const htmlText = '<p>Account notice</p><a href="https://evil.example/reset">Reset</a>';
    const plainRaw = Buffer.from(Buffer.from(plainText, "utf8").toString("base64"), "ascii");
    const htmlRaw = Buffer.from(htmlText.replace(/=/g, "=3D"), "ascii");
    const selection = inspectBodyStructure({
      type: "multipart/alternative",
      childNodes: [
        { part: "1", type: "text/plain", size: plainRaw.length, encoding: "base64", parameters: { charset: "utf-8" } },
        { part: "2", type: "text/html", size: htmlRaw.length, encoding: "quoted-printable", parameters: { charset: "utf-8" } },
      ],
    });
    const client = {
      fetchOne: vi.fn(async () => ({
        bodyParts: new Map<string, Buffer>([
          ["1", plainRaw],
          ["2", htmlRaw],
        ]),
      })),
    };

    const result = await fetchBoundedReadableBodies(client, 77, selection, new AbortController().signal);

    expect(client.fetchOne).toHaveBeenCalledTimes(1);
    expect(result.plain).toContain("readable plain text");
    expect(result.html).toContain("https://evil.example/reset");
    expect(result.truncated).toBe(false);
    expect(result.notes).toEqual([]);
  });

  it("does not confuse the whole message size with selected-part truncation", () => {
    expect(boundedTextPartWasTruncated({
      declaredPartBytes: 120,
      fetchedRawBytes: 120,
      decodedChars: 90,
      rawByteLimit: 48 * 1024,
      decodedCharLimit: 24 * 1024,
    })).toBe(false);

    expect(boundedTextPartWasTruncated({
      declaredPartBytes: 80_000,
      fetchedRawBytes: 48 * 1024,
      decodedChars: 20_000,
      rawByteLimit: 48 * 1024,
      decodedCharLimit: 24 * 1024,
    })).toBe(true);
  });

  it("decodes a standalone fetched text part with its transfer encoding", async () => {
    const value = "hello from iCloud";
    const decoded = await decodeFetchedTextPart(
      Buffer.from(Buffer.from(value).toString("base64"), "ascii"),
      {
        part: "1",
        contentType: "text/plain",
        sizeBytes: null,
        charset: "utf-8",
        transferEncoding: "base64",
      },
      1000,
    );
    expect(decoded.text).toBe(value);
    expect(decoded.truncated).toBe(false);
  });

  it("decodes supported provider charsets and safely falls back", () => {
    expect(decodeTextBuffer(Buffer.from("hello", "utf8"), "utf-8")).toBe("hello");
    expect(decodeTextBuffer(Buffer.from("hello", "utf8"), "not-a-real-charset")).toBe("hello");
  });
});
