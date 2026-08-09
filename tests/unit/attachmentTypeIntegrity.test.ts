import { describe, expect, it } from "vitest";
import type { AttachmentInfo, CanonicalEnvelope } from "../../server/src/canonical/envelope.js";
import { inspectBodyStructure } from "../../server/src/adapters/imap/mimeParts.js";
import { attachmentQrLayer } from "../../server/src/engine/layers/attachmentQr.js";
import { normalizeRawMessage } from "../../server/src/util/mimeNormalize.js";

function envelope(attachments: AttachmentInfo[]): CanonicalEnvelope {
  return {
    provider: "gmail",
    accountProof: "proof",
    messageId: "message-id",
    providerNativeId: "native-id",
    folder: "inbox",
    providerFolderName: "INBOX",
    from: { displayName: "Sender", address: "sender@example.test", domain: "example.test" },
    replyTo: null,
    subject: "Attachment",
    date: new Date(0).toISOString(),
    authentication: { spf: "pass", dkim: "pass", dmarc: "pass", arc: "none" },
    textPreview: "Please review the attachment.",
    htmlSignals: null,
    links: [],
    attachments,
    listHeaders: { listId: null, listUnsubscribe: null, listUnsubscribePost: null },
    threadContext: { isFirstContact: true, threadContinuityBroken: false, replyToChangedMidThread: false },
    parseStatus: "complete",
    parseNotes: [],
    diagnostics: { fetchedAt: new Date(0).toISOString(), sizeBytes: 1000, encoding: "multipart", contentCoverage: "complete" },
  };
}

function attachment(name: string, mimeType: string, extension: string | null = null): AttachmentInfo {
  return {
    name,
    mimeType,
    sizeBytes: 128,
    extension,
    sha256: null,
    suspiciousNamePattern: false,
  };
}

function rawAttachment(mediaType: string, filename: string): Buffer {
  const boundary = "attachment-type-integrity";
  return Buffer.from([
    "From: Sender <sender@example.test>",
    "To: user@example.test",
    "Subject: Attachment",
    "Message-ID: <attachment-type@example.test>",
    "Date: Mon, 10 Aug 2026 10:00:00 +0000",
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
    "MIME-Version: 1.0",
    "",
    `--${boundary}`,
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Please review the attachment.",
    `--${boundary}`,
    `Content-Type: ${mediaType}; name="${filename}"`,
    `Content-Disposition: attachment; filename="${filename}"`,
    "Content-Transfer-Encoding: base64",
    "",
    Buffer.from("synthetic payload", "utf8").toString("base64"),
    `--${boundary}--`,
    "",
  ].join("\r\n"), "utf8");
}

describe("attachment type integrity", () => {
  it("flags a renamed portable executable from its canonical MIME type", () => {
    const result = attachmentQrLayer(envelope([
      attachment("invoice.pdf", "application/vnd.microsoft.portable-executable", "pdf"),
    ]));

    expect(result.evidence).toContainEqual(expect.objectContaining({
      code: "DANGEROUS_ATTACHMENT_MEDIA_TYPE",
      scoreContribution: 6,
    }));
    expect(result.evidence.some((item) => item.code === "DANGEROUS_EXECUTABLE_ATTACHMENT")).toBe(false);
  });

  it("does not double-count MIME evidence when the executable extension already carries the risk", () => {
    const result = attachmentQrLayer(envelope([
      attachment("installer.exe", "application/vnd.microsoft.portable-executable", "exe"),
    ]));

    expect(result.evidence.filter((item) => item.code === "DANGEROUS_EXECUTABLE_ATTACHMENT")).toHaveLength(1);
    expect(result.evidence.some((item) => item.code === "DANGEROUS_ATTACHMENT_MEDIA_TYPE")).toBe(false);
  });

  it("uses declared script MIME type when a script is renamed as text", () => {
    const result = attachmentQrLayer(envelope([
      attachment("instructions.txt", "text/javascript; charset=utf-8", "txt"),
    ]));

    expect(result.evidence).toContainEqual(expect.objectContaining({
      code: "DANGEROUS_ATTACHMENT_MEDIA_TYPE",
      scoreContribution: 6,
    }));
  });

  it("preserves macro-enabled and archive risk when their filenames use harmless extensions", () => {
    const result = attachmentQrLayer(envelope([
      attachment("report.docx", "application/vnd.ms-word.document.macroEnabled.12", "docx"),
      attachment("photos.pdf", "application/zip", "pdf"),
    ]));

    expect(result.evidence).toContainEqual(expect.objectContaining({ code: "MACRO_ENABLED_MEDIA_TYPE", scoreContribution: 4 }));
    expect(result.evidence).toContainEqual(expect.objectContaining({ code: "ARCHIVE_MEDIA_TYPE", scoreContribution: 1 }));
  });

  it("normalizes compatibility dots/trailing whitespace before classifying the filename extension", () => {
    const result = attachmentQrLayer(envelope([
      attachment("invoice.pdf．exe   ", "application/octet-stream", "exe   "),
    ]));

    expect(result.evidence).toContainEqual(expect.objectContaining({
      code: "DANGEROUS_EXECUTABLE_ATTACHMENT",
      scoreContribution: 6,
    }));
  });

  it("flags bidi controls without allowing them to reorder the evidence warning", () => {
    const result = attachmentQrLayer(envelope([
      attachment("invoice\u202Eexe.pdf", "application/pdf", "pdf"),
    ]));
    const bidiEvidence = result.evidence.find((item) => item.code === "BIDI_FILENAME_DISGUISE");

    expect(bidiEvidence).toEqual(expect.objectContaining({ scoreContribution: 4 }));
    expect(bidiEvidence?.description).not.toContain("\u202E");
    expect(bidiEvidence?.description).toContain("invoiceexe.pdf");
  });

  it("keeps an ordinary PDF attachment free of type-integrity evidence", () => {
    const result = attachmentQrLayer(envelope([
      attachment("report.pdf", "application/pdf", "pdf"),
    ]));

    expect(result.evidence).toEqual([]);
  });

  it("carries a renamed dangerous MIME type through raw MIME normalization", async () => {
    const normalized = await normalizeRawMessage(
      rawAttachment("application/vnd.microsoft.portable-executable", "invoice.pdf"),
      {
        provider: "gmail",
        accountProof: "proof",
        providerFolderName: "INBOX",
        normalizedFolder: "inbox",
        providerNativeId: "raw-type-integrity",
      },
    );

    expect(normalized.attachments[0]).toMatchObject({
      name: "invoice.pdf",
      mimeType: "application/vnd.microsoft.portable-executable",
      extension: "pdf",
    });
    expect(attachmentQrLayer(normalized).evidence).toContainEqual(expect.objectContaining({
      code: "DANGEROUS_ATTACHMENT_MEDIA_TYPE",
    }));
  });

  it("carries the same renamed dangerous MIME type through IMAP BODYSTRUCTURE", () => {
    const selection = inspectBodyStructure({
      type: "multipart/mixed",
      childNodes: [
        { part: "1", type: "text/plain", size: 64 },
        {
          part: "2",
          type: "application/vnd.microsoft.portable-executable",
          size: 128,
          disposition: "attachment",
          dispositionParameters: { filename: "invoice.pdf" },
        },
      ],
    });

    expect(selection.attachments[0]).toMatchObject({
      name: "invoice.pdf",
      mimeType: "application/vnd.microsoft.portable-executable",
      extension: "pdf",
    });
    expect(attachmentQrLayer(envelope(selection.attachments)).evidence).toContainEqual(expect.objectContaining({
      code: "DANGEROUS_ATTACHMENT_MEDIA_TYPE",
    }));
  });
});
