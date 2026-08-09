import { describe, expect, it, vi } from "vitest";
import {
  decodeFetchedQrImagePart,
  inspectBodyStructure,
} from "../../server/src/adapters/imap/mimeParts.js";
import { fetchBoundedQrImages } from "../../server/src/adapters/imap/imapAdapter.js";
import { analyzeQrImages } from "../../server/src/util/qrDecode.js";

const QR_URL = "https://secure-login.example.test/verify?session=qr123";
const QR_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAZoAAAGaAQAAAAAefbjOAAAC/0lEQVR4nO2cS26kMBCGvxoj9RKkHKCPYm42miPNDeAofYCR8LIlo5qFH9DJYhT1BDpQXhA68KltpVSPv+yI8ukx/vg8AwYZZJBBBhlk0DEhyaOBsdxJH0REulkglBf6XaZn0IYQqqqKV1XVyeXLAOiA0/x0qneqqsOLr8mgZ6Am/wwd+N8ggEA7IX7qZHlRwMXNp2fQC0BtRPXWwNhBcg/D13yTQa8INe9/4YcZaO+iMDc6Xu/yQbJ48TUZ9AxULKJVIACjOIXQIX5wKnBJBrE2ixdfk0H/AUoVRgf4CaTHKYSmfpxTqbHX9Aza2kc8xIVZFO6iENGxQ7IH2WN6Bm0OlepzAsCpDrgcJoZWy6hP1arPo0PZIgDwGlFNF9VyF1GdsjxhesTxoWoRi2eIyTZILqPVdFlkKrOIQ0M1arjkFEjBYWJtFjo5xaLGOaB11AAeQsdEUajaSJauzCKODpU/cu1h0EYWkTLZxkAxC8sjzgJ5vQujiKjeGqRvc+OLUS4rD5JN5XusyaDnFKpsB9K3ER1Cg/TMtdM1i/Sh2sb3WJNBz0SNmlSmS84eSoc85xHWDT8DVPKIJW0sd+mx15xWpIBhFnF4qNpBlSbbagKLCjGROhxWaxwfqt3wuVFaJWcO7Z9GoImlrxEbxg7ED9tOz6DdoNAAQUSHlEA6xetd5OfkStejVbVa4/hQyRmK2LBKHKpwmfUI62ucAlr1PnPuuEocFu06VjHTLOLgUN2LXTue0/pBLjyx3udpoNXu/He7bBc9In02H3EOqCpUeWQvQMkn/cpeMD3iBFCqPota7aIS3qJ4nUUJLgqhA8Jbih269fQM2hx6f6aLZe9MUrZrEVJfNh9xCiiUQ51+miULEOGScgtGEUm2sdf0DNoPGq+q+usaEbne0yHg1OQi9UN3np5Bm0P+JoK/XR7KjJtIkal2np5BXw19OBs+wLrCgCJF2D7Lc0CP+yyXzNLl/XWLYLVqmL/4mgx6Bvp4zPffw/4zmUEGGWSQQQYZBPAXKTC92Jh9hUIAAAAASUVORK5CYII=",
  "base64",
);

describe("bounded IMAP QR parts", () => {
  it("selects PNG/JPEG QR-capable parts including inline images but ignores unsupported attachments", () => {
    const selection = inspectBodyStructure({
      type: "multipart/mixed",
      childNodes: [
        { part: "1", type: "text/plain", size: 100 },
        { part: "2", type: "image/png", size: 824, encoding: "base64", disposition: "inline", parameters: { name: "inline-qr.png" } },
        { part: "3", type: "image/jpeg", size: 4000, encoding: "base64", disposition: "attachment", dispositionParameters: { filename: "photo.jpg" } },
        { part: "4", type: "application/pdf", size: 5000, disposition: "attachment", dispositionParameters: { filename: "invoice.pdf" } },
        { part: "5", type: "image/gif", size: 500, disposition: "inline" },
      ],
    });
    expect(selection.qrImages).toEqual([
      expect.objectContaining({ part: "2", name: "inline-qr.png", mimeType: "image/png", transferEncoding: "base64" }),
      expect.objectContaining({ part: "3", name: "photo.jpg", mimeType: "image/jpeg", transferEncoding: "base64" }),
    ]);
    expect(selection.qrImages.map((part) => part.part)).not.toContain("4");
    expect(selection.qrImages.map((part) => part.part)).not.toContain("5");
  });

  it("decodes MIME transfer encoding and yields exact image bytes", async () => {
    const decoded = await decodeFetchedQrImagePart(Buffer.from(QR_PNG.toString("base64"), "ascii"), {
      part: "2", name: "qr.png", mimeType: "image/png", sizeBytes: QR_PNG.length, transferEncoding: "base64",
    });
    expect(decoded.equals(QR_PNG)).toBe(true);
    expect(analyzeQrImages([{ name: "qr.png", mimeType: "image/png", content: decoded }]).links[0]?.normalizedUrl).toBe(QR_URL);
  });

  it("rejects a QR MIME-part response shorter than BODYSTRUCTURE declared", async () => {
    const encodedPrefix = Buffer.from(QR_PNG.subarray(0, 16).toString("base64"), "ascii");
    await expect(decodeFetchedQrImagePart(encodedPrefix, {
      part: "2", name: "qr.png", mimeType: "image/png", sizeBytes: QR_PNG.length, transferEncoding: "base64",
    })).rejects.toThrow("fewer MIME-part bytes");
  });

  it("fetches only bounded supported image parts and never requests PDF/full raw source", async () => {
    const selection = inspectBodyStructure({
      type: "multipart/mixed",
      childNodes: [
        { part: "1", type: "text/plain", size: 100 },
        { part: "2", type: "image/png", size: QR_PNG.length, encoding: "base64", disposition: "attachment", dispositionParameters: { filename: "qr.png" } },
        { part: "3", type: "application/pdf", size: 1000, disposition: "attachment", dispositionParameters: { filename: "invoice.pdf" } },
      ],
    });
    const encoded = Buffer.from(QR_PNG.toString("base64"), "ascii");
    const fetchOne = vi.fn(async (_range: string | number, query: Record<string, unknown>) => {
      expect(query).toHaveProperty("bodyParts");
      expect(query).not.toHaveProperty("source");
      expect(query).not.toHaveProperty("bodyStructure");
      const requested = query.bodyParts as Array<{ key: string; start: number; maxLength: number }>;
      expect(requested).toEqual([expect.objectContaining({ key: "2", start: 0 })]);
      expect(requested.map((part) => part.key)).not.toContain("3");
      return { bodyParts: new Map([["2", encoded]]) };
    });
    const result = await fetchBoundedQrImages({ fetchOne }, 77, selection, new AbortController().signal);
    expect(fetchOne).toHaveBeenCalledTimes(1);
    expect(result.supportedCount).toBe(1);
    expect(result.incompleteReasons).toEqual([]);
    expect(result.images).toHaveLength(1);
    expect(result.images[0]?.content.equals(QR_PNG)).toBe(true);
  });

  it("skips declared oversized supported images without downloading their body", async () => {
    const selection = inspectBodyStructure({
      type: "multipart/mixed",
      childNodes: [{ part: "2", type: "image/png", size: 10_000_000, disposition: "attachment", dispositionParameters: { filename: "huge.png" } }],
    });
    const fetchOne = vi.fn();
    const result = await fetchBoundedQrImages({ fetchOne }, 88, selection, new AbortController().signal);
    expect(fetchOne).not.toHaveBeenCalled();
    expect(result.images).toEqual([]);
    expect(result.incompleteReasons.join(" ")).toContain("bounded IMAP image fetch limit");
  });
});
