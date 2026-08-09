import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";
import {
  analyzeQrImages,
  decodeQrImage,
  MAX_QR_IMAGE_BYTES,
  type QrImageInput,
} from "../../server/src/util/qrDecode.js";

const require = createRequire(import.meta.url);
const { PNG } = require("pngjs") as { PNG: { sync: { read: (input: Buffer) => { width: number; height: number; data: Buffer } } } };
const jpeg = require("jpeg-js") as {
  encode: (input: { width: number; height: number; data: Buffer | Uint8Array }, quality?: number) => { data: Buffer };
};

const QR_URL = "https://secure-login.example.test/verify?session=qr123";
const URL_QR_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAZoAAAGaAQAAAAAefbjOAAAC/0lEQVR4nO2cS26kMBCGvxoj9RKkHKCPYm42miPNDeAofYCR8LIlo5qFH9DJYhT1BDpQXhA68KltpVSPv+yI8ukx/vg8AwYZZJBBBhlk0DEhyaOBsdxJH0REulkglBf6XaZn0IYQqqqKV1XVyeXLAOiA0/x0qneqqsOLr8mgZ6Am/wwd+N8ggEA7IX7qZHlRwMXNp2fQC0BtRPXWwNhBcg/D13yTQa8INe9/4YcZaO+iMDc6Xu/yQbJ48TUZ9AxULKJVIACjOIXQIX5wKnBJBrE2ixdfk0H/AUoVRgf4CaTHKYSmfpxTqbHX9Aza2kc8xIVZFO6iENGxQ7IH2WN6Bm0OlepzAsCpDrgcJoZWy6hP1arPo0PZIgDwGlFNF9VyF1GdsjxhesTxoWoRi2eIyTZILqPVdFlkKrOIQ0M1arjkFEjBYWJtFjo5xaLGOaB11AAeQsdEUajaSJauzCKODpU/cu1h0EYWkTLZxkAxC8sjzgJ5vQujiKjeGqRvc+OLUS4rD5JN5XusyaDnFKpsB9K3ER1Cg/TMtdM1i/Sh2sb3WJNBz0SNmlSmS84eSoc85xHWDT8DVPKIJW0sd+mx15xWpIBhFnF4qNpBlSbbagKLCjGROhxWaxwfqt3wuVFaJWcO7Z9GoImlrxEbxg7ED9tOz6DdoNAAQUSHlEA6xetd5OfkStejVbVa4/hQyRmK2LBKHKpwmfUI62ucAlr1PnPuuEocFu06VjHTLOLgUN2LXTue0/pBLjyx3udpoNXu/He7bBc9In02H3EOqCpUeWQvQMkn/cpeMD3iBFCqPota7aIS3qJ4nUUJLgqhA8Jbih269fQM2hx6f6aLZe9MUrZrEVJfNh9xCiiUQ51+miULEOGScgtGEUm2sdf0DNoPGq+q+usaEbne0yHg1OQi9UN3np5Bm0P+JoK/XR7KjJtIkal2np5BXw19OBs+wLrCgCJF2D7Lc0CP+yyXzNLl/XWLYLVqmL/4mgx6Bvp4zPffw/4zmUEGGWSQQQYZBPAXKTC92Jh9hUIAAAAASUVORK5CYII=",
  "base64",
);
const NON_URL_QR_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAG8AAABvAQAAAADKvqPNAAABaElEQVR4nNVUMW7cMBAcHgXQjaW4PEAw+YXrdJWSymW+coc0qWy5S+WDP5B/pONV1CcC8IADUkaUGxmQNWkTw8CydLZbcLic2RlQEX8VV/in3mcLDsAOtmtmwC7SXcVZ8eUQ3B0zHjq6y4sznmO6yGI1buzpxmVKKPtz2ccscBuVf+42rppkMFUxGvd0wL2SwAUqIn0+X24tM+wej6frPo7m5W7rZM7Gfpns1Y/49C3mOHjb1KWZd6DgIEiSPlbeLq0MHhAVObTsTMZkrzujl4akBF4hfVwPm3WHk1LSNgooFh96fRXc8skLewaTn2FIrwcj57nErzSdYSBnA0weaLmYqESBID3vJ9u19uAlGuBiYhV0B6gMMMk0ofI2hRwHsaceUO8n2RTFmdv6MejurdPX7dGV5ufvr6fqRnIQTL7eIZbQD2JEVwCggtuHWoWMyZxvG82gh0aeTFWMWK82+N5LAtV/+Jn/AWnxvNIqIJ44AAAAAElFTkSuQmCC",
  "base64",
);
const CREDENTIAL_URL_QR_PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAG8AAABvAQAAAADKvqPNAAABd0lEQVR4nNVUO27bQBB9KxLYNKJqAxuQV0hHVaucIGfIDSRXqfSBGwMB/LmAfQ65oqrlJYIsIgMuvWsWoQCKL6XtIMawjKcbzGDmvTcPo4gXwRFexf+aRqVOD/dXh49KFUIzGNktXNLbbsW8FxftivHUXG+L+GEQqqY6Ps68jDkFgKzE2e83R71KrUf90NfFpJWbqdInfXKqsVFSM0gyWPY2JymoAcbKZ0jW6JalLB2/5dH9iFXROBlGbw3KJGijKhlG0FxbXlakeEEwOsxhMuQXWpo8QlYyd2jaXdxKRkqB+iQcHo4j03weQBD7oM3CJZtWhvFkpxef/A3AmWykDG58VwAmq2UYsfUT+gn3l26AGtqupvg6K/5Z/Zug7lQLABB1BknGKo8uD5AvGICFM3Nt5uUAi7Kbl37i8mAHeKMyS83eQolqpADQbNPvu/34i/854BVwdfxV4vZ8wFHYLa1XbbIWCY5AlTYbG+pj/8be51Dv8Jn/AS5BwooQEmThAAAAAElFTkSuQmCC",
  "base64",
);

function input(content: Buffer, mimeType = "image/png", name = "qr.png"): QrImageInput {
  return { name, mimeType, content };
}

describe("bounded production QR decoder", () => {
  it("decodes a real PNG QR URL exactly and exposes URL only", () => {
    expect(decodeQrImage(input(URL_QR_PNG))).toEqual({
      name: "qr.png",
      status: "decoded_url",
      url: QR_URL,
    });
  });

  it("decodes a JPEG QR using the same bounded local path", () => {
    const png = PNG.sync.read(URL_QR_PNG);
    const jpegBytes = jpeg.encode({ width: png.width, height: png.height, data: png.data }, 95).data;
    const result = decodeQrImage(input(jpegBytes, "image/jpeg", "qr.jpg"));
    expect(result).toEqual({ name: "qr.jpg", status: "decoded_url", url: QR_URL });
  });

  it("does not turn non-URL QR payloads into link evidence", () => {
    expect(decodeQrImage(input(NON_URL_QR_PNG))).toMatchObject({
      status: "decoded_non_url",
      url: null,
    });
  });

  it("rejects QR URLs containing embedded credentials", () => {
    expect(decodeQrImage(input(CREDENTIAL_URL_QR_PNG))).toMatchObject({
      status: "decoded_non_url",
      url: null,
    });
  });

  it("rejects oversized encoded images before image decompression", () => {
    const huge = Buffer.alloc(MAX_QR_IMAGE_BYTES + 1, 0x41);
    expect(decodeQrImage(input(huge))).toMatchObject({ status: "oversize", url: null });
  });

  it("rejects a PNG dimension bomb before allocating decoded pixels", () => {
    const bomb = Buffer.alloc(24);
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(bomb, 0);
    bomb.write("IHDR", 12, "ascii");
    bomb.writeUInt32BE(100_000, 16);
    bomb.writeUInt32BE(100_000, 20);
    expect(decodeQrImage(input(bomb))).toMatchObject({ status: "oversize", url: null });
  });

  it("returns invalid_image instead of throwing on malformed supported input", () => {
    expect(() => decodeQrImage(input(Buffer.from("not-a-png")))).not.toThrow();
    expect(decodeQrImage(input(Buffer.from("not-a-png")))).toMatchObject({
      status: "invalid_image",
      url: null,
    });
  });

  it("caps per-message QR inspection and marks overflow incomplete", () => {
    const analysis = analyzeQrImages(Array.from({ length: 5 }, (_, index) => input(URL_QR_PNG, "image/png", `qr-${index}.png`)));
    expect(analysis.results).toHaveLength(4);
    expect(analysis.links).toHaveLength(4);
    expect(analysis.incomplete).toBe(true);
    expect(analysis.incompleteReasons.join(" ")).toContain("first 4 supported images");
  });
});
