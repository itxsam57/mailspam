import { createRequire } from "node:module";
import jsQR from "jsqr";
import type { LinkInfo } from "../canonical/envelope.js";

const require = createRequire(import.meta.url);
const { PNG } = require("pngjs") as { PNG: { sync: { read: (input: Buffer) => { width: number; height: number; data: Buffer | Uint8Array } } } };
const jpeg = require("jpeg-js") as {
  decode: (input: Buffer, options?: Record<string, unknown>) => { width: number; height: number; data: Buffer | Uint8Array };
};

export const MAX_QR_IMAGES_PER_MESSAGE = 4;
export const MAX_QR_IMAGE_BYTES = 2 * 1024 * 1024;
export const MAX_QR_IMAGE_PIXELS = 4_000_000;
export const MAX_QR_DIMENSION = 4096;
export const MAX_QR_PAYLOAD_CHARS = 4096;

export type SupportedQrMimeType = "image/png" | "image/jpeg";
export type QrImageStatus =
  | "decoded_url"
  | "no_qr"
  | "decoded_non_url"
  | "oversize"
  | "invalid_image"
  | "unsupported";

export interface QrImageInput {
  name: string;
  mimeType: string;
  content: Buffer;
}

export interface QrImageResult {
  name: string;
  status: QrImageStatus;
  url: string | null;
}

export interface QrAnalysis {
  results: QrImageResult[];
  links: LinkInfo[];
  incomplete: boolean;
  incompleteReasons: string[];
}

function normalizedMimeType(value: string): string {
  return value.split(";", 1)[0]?.trim().toLowerCase() ?? "";
}

export function isSupportedQrImageMimeType(value: string): value is SupportedQrMimeType {
  const mimeType = normalizedMimeType(value);
  return mimeType === "image/png" || mimeType === "image/jpeg";
}

function pngDimensions(buffer: Buffer): { width: number; height: number } | null {
  if (buffer.length < 24) return null;
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (!buffer.subarray(0, 8).equals(signature)) return null;
  if (buffer.toString("ascii", 12, 16) !== "IHDR") return null;
  return { width: buffer.readUInt32BE(16), height: buffer.readUInt32BE(20) };
}

const JPEG_SOF_MARKERS = new Set([
  0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7,
  0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf,
]);

function jpegDimensions(buffer: Buffer): { width: number; height: number } | null {
  if (buffer.length < 4 || buffer[0] !== 0xff || buffer[1] !== 0xd8) return null;
  let offset = 2;
  const scanLimit = Math.min(buffer.length, 128 * 1024);

  while (offset + 4 <= scanLimit) {
    if (buffer[offset] !== 0xff) {
      offset += 1;
      continue;
    }
    while (offset < scanLimit && buffer[offset] === 0xff) offset += 1;
    if (offset >= scanLimit) break;
    const marker = buffer[offset++]!;
    if (marker === 0xd8 || marker === 0xd9) continue;
    if (marker === 0xda) break;
    if (marker >= 0xd0 && marker <= 0xd7) continue;
    if (offset + 2 > scanLimit) return null;
    const length = buffer.readUInt16BE(offset);
    if (length < 2 || offset + length > buffer.length) return null;
    if (JPEG_SOF_MARKERS.has(marker)) {
      if (length < 7 || offset + 7 > buffer.length) return null;
      return {
        height: buffer.readUInt16BE(offset + 3),
        width: buffer.readUInt16BE(offset + 5),
      };
    }
    offset += length;
  }
  return null;
}

function validDimensions(dimensions: { width: number; height: number } | null): dimensions is { width: number; height: number } {
  if (!dimensions) return false;
  if (!Number.isInteger(dimensions.width) || !Number.isInteger(dimensions.height)) return false;
  if (dimensions.width <= 0 || dimensions.height <= 0) return false;
  if (dimensions.width > MAX_QR_DIMENSION || dimensions.height > MAX_QR_DIMENSION) return false;
  return dimensions.width * dimensions.height <= MAX_QR_IMAGE_PIXELS;
}

function normalizeQrUrl(payload: string): string | null {
  const value = payload.trim();
  if (!value || value.length > MAX_QR_PAYLOAD_CHARS) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (url.username || url.password) return null;
    return url.toString();
  } catch {
    return null;
  }
}

function decodePixels(content: Buffer, mimeType: SupportedQrMimeType): { width: number; height: number; data: Uint8ClampedArray } | null {
  const dimensions = mimeType === "image/png" ? pngDimensions(content) : jpegDimensions(content);
  if (!validDimensions(dimensions)) return null;

  const decoded = mimeType === "image/png"
    ? PNG.sync.read(content)
    : jpeg.decode(content, { useTArray: true, formatAsRGBA: true });

  if (!decoded || decoded.width !== dimensions.width || decoded.height !== dimensions.height) return null;
  const expectedLength = decoded.width * decoded.height * 4;
  const data = decoded.data instanceof Uint8ClampedArray
    ? decoded.data
    : new Uint8ClampedArray(decoded.data.buffer, decoded.data.byteOffset, decoded.data.byteLength);
  if (data.byteLength !== expectedLength) return null;
  return { width: decoded.width, height: decoded.height, data };
}

export function decodeQrImage(input: QrImageInput): QrImageResult {
  const mimeType = normalizedMimeType(input.mimeType);
  if (!isSupportedQrImageMimeType(mimeType)) return { name: input.name, status: "unsupported", url: null };
  if (!Buffer.isBuffer(input.content) || input.content.length === 0) {
    return { name: input.name, status: "invalid_image", url: null };
  }
  if (input.content.length > MAX_QR_IMAGE_BYTES) return { name: input.name, status: "oversize", url: null };

  let decoded;
  try {
    decoded = decodePixels(input.content, mimeType);
  } catch {
    return { name: input.name, status: "invalid_image", url: null };
  }
  if (!decoded) {
    const dimensions = mimeType === "image/png" ? pngDimensions(input.content) : jpegDimensions(input.content);
    return {
      name: input.name,
      status: dimensions && !validDimensions(dimensions) ? "oversize" : "invalid_image",
      url: null,
    };
  }

  let qr;
  try {
    qr = jsQR(decoded.data, decoded.width, decoded.height, { inversionAttempts: "attemptBoth" });
  } catch {
    return { name: input.name, status: "invalid_image", url: null };
  }
  if (!qr?.data) return { name: input.name, status: "no_qr", url: null };
  const url = normalizeQrUrl(qr.data);
  if (!url) return { name: input.name, status: "decoded_non_url", url: null };
  return { name: input.name, status: "decoded_url", url };
}

export function analyzeQrImages(inputs: QrImageInput[]): QrAnalysis {
  const results: QrImageResult[] = [];
  const links: LinkInfo[] = [];
  const incompleteReasons: string[] = [];
  const supported = inputs.filter((input) => isSupportedQrImageMimeType(input.mimeType));

  for (const input of supported.slice(0, MAX_QR_IMAGES_PER_MESSAGE)) {
    const result = decodeQrImage(input);
    results.push(result);
    if (result.status === "decoded_url" && result.url) {
      links.push({
        visibleText: null,
        rawUrl: result.url,
        normalizedUrl: result.url,
        claimedBrand: null,
        brandDomainMismatch: null,
        source: "qr",
      });
    } else if (result.status === "oversize") {
      incompleteReasons.push(`QR-capable image \"${input.name}\" exceeded the local scan limit.`);
    } else if (result.status === "invalid_image") {
      incompleteReasons.push(`QR-capable image \"${input.name}\" could not be decoded safely.`);
    }
  }

  if (supported.length > MAX_QR_IMAGES_PER_MESSAGE) {
    incompleteReasons.push(`Only the first ${MAX_QR_IMAGES_PER_MESSAGE} supported images were inspected for QR codes.`);
  }

  return {
    results,
    links,
    incomplete: incompleteReasons.length > 0,
    incompleteReasons,
  };
}
