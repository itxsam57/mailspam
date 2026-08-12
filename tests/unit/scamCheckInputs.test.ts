import { describe, expect, it } from "vitest";
import {
  ConsumerScamInputError,
  evaluateSubmittedEml,
  evaluateSubmittedImage,
  MAX_SUBMITTED_EML_BYTES,
} from "../../server/src/consumer/scamCheckInputs.js";

const QR_URL = "https://secure-login.example.test/verify?session=qr123";
const URL_QR_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAZoAAAGaAQAAAAAefbjOAAAC/0lEQVR4nO2cS26kMBCGvxoj9RKkHKCPYm42miPNDeAofYCR8LIlo5qFH9DJYhT1BDpQXhA68KltpVSPv+yI8ukx/vg8AwYZZJBBBhlk0DEhyaOBsdxJH0REulkglBf6XaZn0IYQqqqKV1XVyeXLAOiA0/x0qneqqsOLr8mgZ6Am/wwd+N8ggEA7IX7qZHlRwMXNp2fQC0BtRPXWwNhBcg/D13yTQa8INe9/4YcZaO+iMDc6Xu/yQbJ48TUZ9AxULKJVIACjOIXQIX5wKnBJBrE2ixdfk0H/AUoVRgf4CaTHKYSmfpxTqbHX9Aza2kc8xIVZFO6iENGxQ7IH2WN6Bm0OlepzAsCpDrgcJoZWy6hP1arPo0PZIgDwGlFNF9VyF1GdsjxhesTxoWoRi2eIyTZILqPVdFlkKrOIQ0M1arjkFEjBYWJtFjo5xaLGOaB11AAeQsdEUajaSJauzCKODpU/cu1h0EYWkTLZxkAxC8sjzgJ5vQujiKjeGqRvc+OLUS4rD5JN5XusyaDnFKpsB9K3ER1Cg/TMtdM1i/Sh2sb3WJNBz0SNmlSmS84eSoc85xHWDT8DVPKIJW0sd+mx15xWpIBhFnF4qNpBlSbbagKLCjGROhxWaxwfqt3wuVFaJWcO7Z9GoImlrxEbxg7ED9tOz6DdoNAAQUSHlEA6xetd5OfkStejVbVa4/hQyRmK2LBKHKpwmfUI62ucAlr1PnPuuEocFu06VjHTLOLgUN2LXTue0/pBLjyx3udpoNXu/He7bBc9In02H3EOqCpUeWQvQMkn/cpeMD3iBFCqPota7aIS3qJ4nUUJLgqhA8Jbih269fQM2hx6f6aLZe9MUrZrEVJfNh9xCiiUQ51+miULEOGScgtGEUm2sdf0DNoPGq+q+usaEbne0yHg1OQi9UN3np5Bm0P+JoK/XR7KjJtIkal2np5BXw19OBs+wLrCgCJF2D7Lc0CP+yyXzNLl/XWLYLVqmL/4mgx6Bvp4zPffw/4zmUEGGWSQQQYZBPAXKTC92Jh9hUIAAAAASUVORK5CYII=",
  "base64",
);

function eml(body: string, auth = ""): Buffer {
  const headers = [
    "From: Billing Team <billing@example.net>",
    "To: owner@example.com",
    "Subject: Subscription renewed",
    "Message-ID: <submitted-message@example.net>",
    "Date: Wed, 12 Aug 2026 20:00:00 +0000",
    ...(auth ? [auth] : []),
    "Content-Type: text/plain; charset=utf-8",
  ];
  return Buffer.from(`${headers.join("\r\n")}\r\n\r\n${body}\r\n`, "utf8");
}

describe("Scam Check binary input convergence", () => {
  it("runs uploaded EML through the same message-intent and link engine", async () => {
    const result = await evaluateSubmittedEml(eml(
      "Your subscription renewed. If this was not you, call now at (555) 123-4567 or visit http://192.0.2.44/login",
    ), { intelligenceEntries: [] });

    expect(result.evidence.some((item) => item.code === "CALLBACK_SCAM_INTENT")).toBe(true);
    expect(result.evidence.some((item) => item.code === "RAW_IP_HOST")).toBe(true);
    expect(result.verdict).toBe("high_risk");
  });

  it("never trusts Authentication-Results embedded inside a user-controlled EML", async () => {
    const result = await evaluateSubmittedEml(eml(
      "Normal meeting reminder for tomorrow morning.",
      "Authentication-Results: attacker.example; spf=pass smtp.mailfrom=example.net; dkim=pass header.d=example.net header.s=x; dmarc=pass header.from=example.net",
    ), { intelligenceEntries: [] });

    const transport = result.layerResults.find((layer) => layer.layer === "transport_auth");
    expect(transport?.incomplete).toBe(true);
    expect(transport?.evidence).toEqual([]);
    expect(result.explanation.limitations.join(" ")).toMatch(/never treated as trusted provider authentication provenance/i);
  });

  it("rejects oversized EML before MIME parsing", async () => {
    await expect(evaluateSubmittedEml(Buffer.alloc(MAX_SUBMITTED_EML_BYTES + 1, 0x41)))
      .rejects.toBeInstanceOf(ConsumerScamInputError);
  });

  it("decodes QR locally and lets verified signed URL intelligence confirm it", async () => {
    const result = await evaluateSubmittedImage({
      content: URL_QR_PNG,
      mimeType: "image/png",
      name: "suspicious-qr.png",
    }, {
      intelligenceEntries: [{
        type: "url",
        value: QR_URL,
        confirmedThreat: true,
        ruleId: "test-confirmed-qr-url",
      }],
    });

    expect(result.evidence.some((item) => item.code === "GLOBAL_CONFIRMED_MATCH")).toBe(true);
    expect(result.verdict).toBe("confirmed_threat");
  });

  it("never labels an image Safe when visible text could not be inspected", async () => {
    const result = await evaluateSubmittedImage({
      content: URL_QR_PNG,
      mimeType: "image/png",
    }, { intelligenceEntries: [] });

    expect(result.verdict).not.toBe("safe");
    expect(result.explanation.limitations.join(" ")).toMatch(/visual-text extractor|visible screenshot\/image text/i);
  });

  it("feeds bounded local OCR output into the existing full-context detector", async () => {
    const result = await evaluateSubmittedImage({
      content: URL_QR_PNG,
      mimeType: "image/png",
    }, { intelligenceEntries: [] }, {
      visualTextExtractor: {
        extract: async () => ({
          text: "Your subscription renewed. Call now at (555) 123-4567 or use http://192.0.2.44/login",
          complete: true,
        }),
      },
    });

    expect(result.evidence.some((item) => item.code === "CALLBACK_SCAM_INTENT")).toBe(true);
    expect(result.evidence.some((item) => item.code === "RAW_IP_HOST")).toBe(true);
    expect(result.verdict).toBe("high_risk");
  });

  it("rejects unsupported image formats rather than sending them to a cloud fallback", async () => {
    await expect(evaluateSubmittedImage({
      content: Buffer.from("GIF89a", "ascii"),
      mimeType: "image/gif",
    })).rejects.toMatchObject({ code: "unsupported_image" });
  });
});
