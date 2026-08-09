import { describe, expect, it } from "vitest";
import { normalizeRawMessage } from "../../server/src/util/mimeNormalize.js";
import { attachmentQrLayer } from "../../server/src/engine/layers/attachmentQr.js";
import { scanMessage } from "../../server/src/engine/pipeline.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";

const QR_URL = "https://secure-login.example.test/verify?session=qr123";
const QR_PNG_BASE64 = "iVBORw0KGgoAAAANSUhEUgAAAZoAAAGaAQAAAAAefbjOAAAC/0lEQVR4nO2cS26kMBCGvxoj9RKkHKCPYm42miPNDeAofYCR8LIlo5qFH9DJYhT1BDpQXhA68KltpVSPv+yI8ukx/vg8AwYZZJBBBhlk0DEhyaOBsdxJH0REulkglBf6XaZn0IYQqqqKV1XVyeXLAOiA0/x0qneqqsOLr8mgZ6Am/wwd+N8ggEA7IX7qZHlRwMXNp2fQC0BtRPXWwNhBcg/D13yTQa8INe9/4YcZaO+iMDc6Xu/yQbJ48TUZ9AxULKJVIACjOIXQIX5wKnBJBrE2ixdfk0H/AUoVRgf4CaTHKYSmfpxTqbHX9Aza2kc8xIVZFO6iENGxQ7IH2WN6Bm0OlepzAsCpDrgcJoZWy6hP1arPo0PZIgDwGlFNF9VyF1GdsjxhesTxoWoRi2eIyTZILqPVdFlkKrOIQ0M1arjkFEjBYWJtFjo5xaLGOaB11AAeQsdEUajaSJauzCKODpU/cu1h0EYWkTLZxkAxC8sjzgJ5vQujiKjeGqRvc+OLUS4rD5JN5XusyaDnFKpsB9K3ER1Cg/TMtdM1i/Sh2sb3WJNBz0SNmlSmS84eSoc85xHWDT8DVPKIJW0sd+mx15xWpIBhFnF4qNpBlSbbagKLCjGROhxWaxwfqt3wuVFaJWcO7Z9GoImlrxEbxg7ED9tOz6DdoNAAQUSHlEA6xetd5OfkStejVbVa4/hQyRmK2LBKHKpwmfUI62ucAlr1PnPuuEocFu06VjHTLOLgUN2LXTue0/pBLjyx3udpoNXu/He7bBc9In02H3EOqCpUeWQvQMkn/cpeMD3iBFCqPota7aIS3qJ4nUUJLgqhA8Jbih269fQM2hx6f6aLZe9MUrZrEVJfNh9xCiiUQ51+miULEOGScgtGEUm2sdf0DNoPGq+q+usaEbne0yHg1OQi9UN3np5Bm0P+JoK/XR7KjJtIkal2np5BXw19OBs+wLrCgCJF2D7Lc0CP+yyXzNLl/XWLYLVqmL/4mgx6Bvp4zPffw/4zmUEGGWSQQQYZBPAXKTC92Jh9hUIAAAAASUVORK5CYII=";

function messageWithQr(base64 = QR_PNG_BASE64): string {
  return [
    "From: Billing Notice <billing@example.test>",
    "To: user@example.test",
    "Subject: Review the attached account notice",
    "Message-ID: <qr-message@example.test>",
    "Date: Sun, 9 Aug 2026 16:00:00 +0000",
    "Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass",
    "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="qr-boundary"',
    "",
    "--qr-boundary",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Please review the attached account notice.",
    "--qr-boundary",
    'Content-Type: image/png; name="account-qr.png"',
    "Content-Transfer-Encoding: base64",
    'Content-Disposition: attachment; filename="account-qr.png"',
    "",
    base64,
    "--qr-boundary--",
    "",
  ].join("\r\n");
}

describe("QR MIME normalization", () => {
  it("turns only the locally decoded QR URL into canonical link evidence", async () => {
    const envelope = await normalizeRawMessage(messageWithQr(), {
      provider: "gmail",
      accountProof: "a".repeat(64),
      providerFolderName: "INBOX",
      normalizedFolder: "inbox",
      providerNativeId: "provider-message-1",
    });

    const qrLinks = envelope.links.filter((link) => link.source === "qr");
    expect(qrLinks).toEqual([{
      visibleText: null,
      rawUrl: QR_URL,
      normalizedUrl: QR_URL,
      claimedBrand: null,
      brandDomainMismatch: null,
      source: "qr",
    }]);
    expect(envelope.diagnostics.qrInspection).toMatchObject({
      supportedImages: 1,
      decodedUrlCount: 1,
      incomplete: false,
    });
    expect(envelope.attachments).toHaveLength(1);
    expect(envelope.attachments[0]).not.toHaveProperty("content");

    const serialized = JSON.stringify(envelope);
    expect(serialized).not.toContain(QR_PNG_BASE64.slice(0, 80));
    expect(serialized).not.toContain("iVBORw0KGgo");
  });

  it("produces QR attachment evidence and at least Review without pretending the destination is confirmed malicious", async () => {
    const envelope = await normalizeRawMessage(messageWithQr(), {
      provider: "gmail",
      accountProof: "a".repeat(64),
      providerFolderName: "INBOX",
      normalizedFolder: "inbox",
      providerNativeId: "provider-message-2",
    });

    const layer = attachmentQrLayer(envelope);
    expect(layer.evidence.some((item) => item.code === "QR_CODE_URL_PAYLOAD")).toBe(true);
    expect(layer.incomplete).toBe(false);

    const result = scanMessage(envelope, {
      personalPolicy: new InMemoryPersonalPolicyStore(),
      threatFeed: { getVerifiedEntries: () => [] },
    });
    expect(["review", "high_risk"]).toContain(result.scored.verdict);
    expect(result.scored.evidence.some((item) => item.code === "QR_CODE_URL_PAYLOAD")).toBe(true);
  });

  it("blocks a Safe verdict when a supported QR-capable image cannot be inspected safely", async () => {
    const malformedImage = Buffer.from("not-a-real-png").toString("base64");
    const envelope = await normalizeRawMessage(messageWithQr(malformedImage), {
      provider: "gmail",
      accountProof: "a".repeat(64),
      providerFolderName: "INBOX",
      normalizedFolder: "inbox",
      providerNativeId: "provider-message-3",
    });

    expect(envelope.diagnostics.qrInspection?.incomplete).toBe(true);
    const layer = attachmentQrLayer(envelope);
    expect(layer.incomplete).toBe(true);
    expect(layer.blocksSafeVerdict).toBe(true);

    const result = scanMessage(envelope, {
      personalPolicy: new InMemoryPersonalPolicyStore(),
      threatFeed: { getVerifiedEntries: () => [] },
    });
    expect(result.scored.verdict).not.toBe("safe");
  });
});
