import { describe, expect, it } from "vitest";
import { normalizeRawMessage } from "../../server/src/util/mimeNormalize.js";

describe("mailparser production dependency compatibility", () => {
  it("keeps HTML-only MIME parsing and text extraction working through Email Shield normalization", async () => {
    const source = [
      "From: sender@example.com",
      "To: recipient@example.com",
      "Subject: HTML-only compatibility fixture",
      "MIME-Version: 1.0",
      "Content-Type: text/html; charset=utf-8",
      "Content-Transfer-Encoding: quoted-printable",
      "",
      "<html><body><h1>Security notice</h1><p>Hello <strong>world</strong>.</p><a href=3D\"https://example.com/path\">Review details</a></body></html>",
      "",
    ].join("\r\n");

    const envelope = await normalizeRawMessage(source, {
      provider: "icloud",
      accountProof: "dependency-compatibility-proof",
      providerFolderName: "INBOX",
      normalizedFolder: "inbox",
      providerNativeId: "dependency-compatibility-message",
    });

    expect(envelope.subject).toBe("HTML-only compatibility fixture");
    expect(envelope.parseStatus).toBe("complete");
    expect(envelope.htmlSignals?.extractedText).toContain("Security notice");
    expect(envelope.htmlSignals?.extractedText).toContain("Hello world");
    expect(envelope.htmlSignals?.extractedText).toContain("Review details");
    expect(envelope.links.map((link) => link.normalizedUrl)).toContain("https://example.com/path");
  });
});
