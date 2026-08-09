import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

function source(path: string): string {
  return readFileSync(resolve(process.cwd(), path), "utf8");
}

describe("QR decoder architecture", () => {
  it("keeps image bytes outside the canonical message and browser contracts", () => {
    const envelope = source("src/canonical/envelope.ts");
    const qrDecoder = source("src/util/qrDecode.ts");
    const mimeNormalizer = source("src/util/mimeNormalize.ts");

    const attachmentInterface = envelope.match(/export interface AttachmentInfo \{([\s\S]*?)\n\}/)?.[1] ?? "";
    expect(attachmentInterface).not.toMatch(/content|bytes|buffer|base64/i);
    expect(envelope).toContain('source?: "body" | "qr"');
    expect(qrDecoder).toContain("MAX_QR_IMAGE_BYTES");
    expect(qrDecoder).toContain("MAX_QR_IMAGE_PIXELS");
    expect(qrDecoder).toContain("MAX_QR_IMAGES_PER_MESSAGE");
    expect(mimeNormalizer).toContain("qrAnalysis.links");
    expect(mimeNormalizer).not.toContain("attachments: mail.attachments");
  });

  it("keeps IMAP QR acquisition bounded and separate from generic attachment downloads", () => {
    const adapter = source("src/adapters/imap/imapAdapter.ts");
    const parts = source("src/adapters/imap/mimeParts.ts");

    expect(adapter).toContain("fetchBoundedQrImages");
    expect(adapter).toContain("MAX_ENCODED_QR_PART_BYTES");
    expect(adapter).toContain("MAX_QR_IMAGES_PER_MESSAGE");
    expect(adapter).toContain("bodyParts: fetchable.map");
    expect(adapter).not.toMatch(/downloadAttachment|fetchAttachment|attachmentContent/i);
    expect(parts).toContain('mimeType: "image/png" | "image/jpeg"');
  });

  it("does not add provider permissions or external QR/image network calls", () => {
    const decoder = source("src/util/qrDecode.ts");
    const gmail = source("src/adapters/gmail/gmailAdapter.ts");
    const outlook = source("src/adapters/outlook/outlookAdapter.ts");

    expect(decoder).not.toMatch(/fetch\(|https?:\/\//);
    expect(gmail).not.toContain("gmail.readonly");
    expect(outlook).not.toContain("Mail.Read.All");
  });
});
