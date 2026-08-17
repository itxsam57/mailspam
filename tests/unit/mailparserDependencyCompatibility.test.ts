import { describe, expect, it } from "vitest";
import { simpleParser } from "mailparser";

describe("mailparser production dependency compatibility", () => {
  it("keeps HTML-only MIME parsing and html-to-text conversion working under the audited dependency graph", async () => {
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

    const parsed = await simpleParser(source);

    expect(parsed.subject).toBe("HTML-only compatibility fixture");
    expect(typeof parsed.html).toBe("string");
    expect(parsed.html).toContain("https://example.com/path");
    expect(parsed.text).toContain("Security notice");
    expect(parsed.text).toContain("Hello world");
    expect(parsed.text).toContain("Review details");
  });
});
