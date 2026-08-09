import { lookup as dnsLookup } from "node:dns/promises";
import http, { type IncomingHttpHeaders } from "node:http";
import https from "node:https";
import { isIP } from "node:net";

/**
 * Hardened isolated resolver for the explicit Analyze Links action.
 *
 * Security properties:
 * - only HTTP(S), no URL userinfo, no mailbox cookies/auth headers;
 * - resolves a hostname exactly once per redirect hop;
 * - rejects a hop if any resolved address is non-public;
 * - pins the socket to one address from that validated DNS answer, so the
 *   transport never performs a second DNS lookup that could be rebound;
 * - repeats resolve/validate/pin for every redirect hop;
 * - max 3 redirects, 512 KiB body, text/html or text/plain only, 5 s total;
 * - refuses partial/oversized/compressed bodies instead of treating them as
 *   successfully inspected content.
 *
 * This module never runs during mailbox scanning. It is used only by the
 * explicit per-message Analyze Links action.
 */

export const MAX_ANALYZE_REDIRECTS = 3;
export const MAX_ANALYZE_BODY_BYTES = 512 * 1024;
export const ANALYZE_TOTAL_TIMEOUT_MS = 5000;
const ALLOWED_CONTENT_TYPES = new Set(["text/html", "text/plain"]);

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

interface PinnedResponse {
  statusCode: number;
  headers: IncomingHttpHeaders;
  body: AsyncIterable<Uint8Array>;
  cancel(): void;
}

export interface HardenedFetchDependencies {
  resolveHost?: (hostname: string) => Promise<ResolvedAddress[]>;
  requestPinned?: (
    target: URL,
    pinned: ResolvedAddress,
    signal: AbortSignal,
  ) => Promise<PinnedResponse>;
  now?: () => number;
  timeoutMs?: number;
  maxBodyBytes?: number;
  maxRedirects?: number;
}

export type HardenedFetchResult = {
  finalUrl: string;
  contentType: string;
  body: string;
};

function stripIpv6Brackets(value: string): string {
  const unwrapped = value.startsWith("[") && value.endsWith("]")
    ? value.slice(1, -1)
    : value;
  const zone = unwrapped.indexOf("%");
  return zone >= 0 ? unwrapped.slice(0, zone) : unwrapped;
}

function parseIpv4(address: string): number[] | null {
  if (isIP(address) !== 4) return null;
  const octets = address.split(".").map(Number);
  return octets.length === 4 && octets.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)
    ? octets
    : null;
}

function parseIpv6(address: string): bigint | null {
  const bare = stripIpv6Brackets(address).toLowerCase();
  if (isIP(bare) !== 6) return null;

  let normalized = bare;
  const lastColon = normalized.lastIndexOf(":");
  const tail = normalized.slice(lastColon + 1);
  if (tail.includes(".")) {
    const ipv4 = parseIpv4(tail);
    if (!ipv4) return null;
    const high = ((ipv4[0]! << 8) | ipv4[1]!).toString(16);
    const low = ((ipv4[2]! << 8) | ipv4[3]!).toString(16);
    normalized = `${normalized.slice(0, lastColon)}:${high}:${low}`;
  }

  const halves = normalized.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":").filter(Boolean) : [];
  const right = halves.length === 2 && halves[1]
    ? halves[1].split(":").filter(Boolean)
    : [];
  const missing = 8 - left.length - right.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;

  const groups = halves.length === 2
    ? [...left, ...Array(missing).fill("0"), ...right]
    : [...left, ...right];
  if (groups.length !== 8) return null;

  let value = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    value = (value << 16n) | BigInt(`0x${group}`);
  }
  return value;
}

function ipv6PrefixMatches(value: bigint, network: bigint, prefixLength: number): boolean {
  const shift = BigInt(128 - prefixLength);
  return (value >> shift) === (network >> shift);
}

/** Returns true only for addresses that are safe to contact as public Internet destinations. */
export function isPublicAnalyzeAddress(address: string): boolean {
  const bare = stripIpv6Brackets(address);
  const ipv4 = parseIpv4(bare);
  if (ipv4) {
    const [a, b, c] = ipv4;
    if (a === 0 || a === 10 || a === 127) return false;
    if (a === 100 && b! >= 64 && b! <= 127) return false; // shared carrier space
    if (a === 169 && b === 254) return false;
    if (a === 172 && b! >= 16 && b! <= 31) return false;
    if (a === 192 && b === 0 && c === 0) return false;
    if (a === 192 && b === 0 && c === 2) return false; // documentation
    if (a === 192 && b === 88 && c === 99) return false;
    if (a === 192 && b === 168) return false;
    if (a === 198 && (b === 18 || b === 19)) return false; // benchmark
    if (a === 198 && b === 51 && c === 100) return false; // documentation
    if (a === 203 && b === 0 && c === 113) return false; // documentation
    if (a! >= 224) return false; // multicast/reserved/broadcast
    return true;
  }

  const ipv6 = parseIpv6(bare);
  if (ipv6 === null) return false;
  if (ipv6 === 0n || ipv6 === 1n) return false;

  // Reject IPv4-mapped, translation/tunnelling and special-purpose ranges so
  // a private IPv4 target cannot be smuggled through an IPv6 representation.
  if (ipv6PrefixMatches(ipv6, 0xffffn << 32n, 96)) return false; // ::ffff:0:0/96
  if (ipv6PrefixMatches(ipv6, 0x64ff9bn << 96n, 96)) return false; // 64:ff9b::/96
  if (ipv6PrefixMatches(ipv6, 0x64ff9b0001n << 80n, 48)) return false; // 64:ff9b:1::/48
  if (ipv6PrefixMatches(ipv6, 0x100n << 112n, 64)) return false; // 100::/64
  if (ipv6PrefixMatches(ipv6, 0x20010000n << 96n, 32)) return false; // Teredo 2001:0000::/32
  if (ipv6PrefixMatches(ipv6, 0x20010db8n << 96n, 32)) return false; // documentation
  if (ipv6PrefixMatches(ipv6, 0x2002n << 112n, 16)) return false; // 6to4

  const topByte = Number(ipv6 >> 120n);
  const top16 = Number(ipv6 >> 112n);
  // Public Internet IPv6 unicast is currently allocated from 2000::/3.
  // Treat every other range as non-public for this outbound analyzer.
  if ((top16 & 0xe000) !== 0x2000) return false;
  if ((topByte & 0xfe) === 0xfc) return false; // unique local fc00::/7
  if ((top16 & 0xffc0) === 0xfe80) return false; // link local fe80::/10
  if ((top16 & 0xffc0) === 0xfec0) return false; // deprecated site-local
  if (topByte === 0xff) return false; // multicast
  return true;
}

async function defaultResolveHost(hostname: string): Promise<ResolvedAddress[]> {
  const normalized = stripIpv6Brackets(hostname);
  const literalFamily = isIP(normalized);
  if (literalFamily === 4 || literalFamily === 6) {
    return [{ address: normalized, family: literalFamily }];
  }

  const records = await dnsLookup(normalized, { all: true, verbatim: true });
  return records.map((record) => ({
    address: record.address,
    family: record.family === 6 ? 6 : 4,
  }));
}

function defaultPinnedRequest(
  target: URL,
  pinned: ResolvedAddress,
  signal: AbortSignal,
): Promise<PinnedResponse> {
  return new Promise((resolve, reject) => {
    const headers = {
      Host: target.host,
      "User-Agent": "EmailShieldLinkAnalyzer/1.0",
      Accept: "text/html,text/plain;q=0.9,*/*;q=0.1",
      "Accept-Encoding": "identity",
      Connection: "close",
    };
    const path = `${target.pathname}${target.search}` || "/";
    const common: http.RequestOptions = {
      protocol: target.protocol,
      hostname: pinned.address,
      family: pinned.family,
      port: target.port ? Number(target.port) : undefined,
      method: "GET",
      path,
      headers,
      agent: false,
    };

    const onResponse = (response: http.IncomingMessage) => {
      resolve({
        statusCode: response.statusCode ?? 0,
        headers: response.headers,
        body: response,
        cancel: () => response.destroy(),
      });
    };

    const originalHostname = stripIpv6Brackets(target.hostname);
    const request = target.protocol === "https:"
      ? https.request(
          {
            ...common,
            // TCP goes to pinned.address; SNI/certificate verification stays
            // bound to the original DNS hostname instead of the IP.
            servername: isIP(originalHostname) === 0 ? originalHostname : undefined,
          },
          onResponse,
        )
      : http.request(common, onResponse);

    const abort = () => request.destroy(new Error("Analyze Links request aborted."));
    if (signal.aborted) {
      abort();
      return;
    }
    signal.addEventListener("abort", abort, { once: true });
    request.once("close", () => signal.removeEventListener("abort", abort));
    request.once("error", reject);
    request.end();
  });
}

function normalizedContentType(headers: IncomingHttpHeaders): string {
  const value = Array.isArray(headers["content-type"])
    ? headers["content-type"][0] ?? ""
    : headers["content-type"] ?? "";
  return value.split(";", 1)[0]!.trim().toLowerCase();
}

function firstHeader(headers: IncomingHttpHeaders, name: string): string | null {
  const value = headers[name];
  if (Array.isArray(value)) return value[0] ?? null;
  return typeof value === "string" ? value : null;
}

async function readBoundedBody(
  response: PinnedResponse,
  maxBodyBytes: number,
  deadline: number,
  now: () => number,
): Promise<string | null> {
  const declaredLength = Number(firstHeader(response.headers, "content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maxBodyBytes) {
    response.cancel();
    return null;
  }

  const contentEncoding = (firstHeader(response.headers, "content-encoding") ?? "identity").trim().toLowerCase();
  if (contentEncoding && contentEncoding !== "identity") {
    response.cancel();
    return null;
  }

  let received = 0;
  const chunks: Buffer[] = [];
  try {
    for await (const chunk of response.body) {
      if (now() >= deadline) {
        response.cancel();
        return null;
      }
      const buffer = Buffer.from(chunk);
      received += buffer.length;
      if (received > maxBodyBytes) {
        response.cancel();
        return null;
      }
      chunks.push(buffer);
    }
  } catch {
    return null;
  }
  return Buffer.concat(chunks).toString("utf8");
}

function choosePinnedAddress(addresses: ResolvedAddress[]): ResolvedAddress | null {
  return addresses.find((entry) => entry.family === 4) ?? addresses[0] ?? null;
}

export function createHardenedFetch(dependencies: HardenedFetchDependencies = {}) {
  const resolveHost = dependencies.resolveHost ?? defaultResolveHost;
  const requestPinned = dependencies.requestPinned ?? defaultPinnedRequest;
  const now = dependencies.now ?? Date.now;
  const timeoutMs = dependencies.timeoutMs ?? ANALYZE_TOTAL_TIMEOUT_MS;
  const maxBodyBytes = dependencies.maxBodyBytes ?? MAX_ANALYZE_BODY_BYTES;
  const maxRedirects = dependencies.maxRedirects ?? MAX_ANALYZE_REDIRECTS;

  return async function fetchAnalyzedDestination(url: string): Promise<HardenedFetchResult | null> {
    const deadline = now() + timeoutMs;
    let current = url;

    for (let hop = 0; hop <= maxRedirects; hop++) {
      if (now() >= deadline) return null;

      let target: URL;
      try {
        target = new URL(current);
      } catch {
        return null;
      }
      if (target.protocol !== "http:" && target.protocol !== "https:") return null;
      if (target.username || target.password) return null;

      const hostname = stripIpv6Brackets(target.hostname);
      let addresses: ResolvedAddress[];
      try {
        addresses = await resolveHost(hostname);
      } catch {
        return null;
      }
      if (addresses.length === 0) return null;
      if (addresses.some((entry) => !isPublicAnalyzeAddress(entry.address))) return null;
      const pinned = choosePinnedAddress(addresses);
      if (!pinned) return null;

      const remaining = deadline - now();
      if (remaining <= 0) return null;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), remaining);

      let response: PinnedResponse;
      try {
        response = await requestPinned(target, pinned, controller.signal);
      } catch {
        clearTimeout(timer);
        return null;
      }

      try {
        if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
          const location = firstHeader(response.headers, "location");
          response.cancel();
          if (!location || hop >= maxRedirects) return null;
          try {
            current = new URL(location, target).toString();
          } catch {
            return null;
          }
          continue;
        }

        const contentType = normalizedContentType(response.headers);
        if (!ALLOWED_CONTENT_TYPES.has(contentType)) {
          response.cancel();
          return { finalUrl: target.toString(), contentType, body: "" };
        }

        const body = await readBoundedBody(response, maxBodyBytes, deadline, now);
        if (body === null) return null;
        return { finalUrl: target.toString(), contentType, body };
      } finally {
        clearTimeout(timer);
      }
    }

    return null;
  };
}

export const hardenedFetch = createHardenedFetch();
