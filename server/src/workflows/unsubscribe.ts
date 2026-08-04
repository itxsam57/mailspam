import { lookup } from "node:dns/promises";
import { request } from "node:https";
import { isIP } from "node:net";
import type { CanonicalEnvelope } from "../canonical/envelope.js";

export interface UnsubscribeCapability {
  available: boolean;
  method: "one_click_post" | "mailto" | "link_only" | "none";
  target: string | null;
}

export interface OneClickUnsubscribeResult {
  success: boolean;
  status?: number;
  reason?: string;
}

export interface OneClickPostResponse {
  status: number;
}

const ONE_CLICK_BODY = "List-Unsubscribe=One-Click";
const MAX_TARGET_LENGTH = 2048;
const REQUEST_TIMEOUT_MS = 10_000;

/** Prefer RFC 8058 one-click POST. Bare links and mailto values are surfaced
 * for an explicit user-managed flow only; Email Shield never auto-opens them. */
export function unsubscribeCapability(envelope: CanonicalEnvelope): UnsubscribeCapability {
  const { listUnsubscribe, listUnsubscribePost } = envelope.listHeaders;
  if (!listUnsubscribe) return { available: false, method: "none", target: null };

  const isOneClick = listUnsubscribePost?.toLowerCase().includes("one-click") ?? false;
  const mailtoMatch = listUnsubscribe.match(/mailto:([^>\s,]+)/i);
  const httpMatch = listUnsubscribe.match(/https?:\/\/[^>\s,]+/i);

  if (isOneClick && httpMatch) {
    return { available: true, method: "one_click_post", target: httpMatch[0] };
  }
  if (httpMatch) {
    return { available: true, method: "link_only", target: httpMatch[0] };
  }
  if (mailtoMatch) {
    return { available: true, method: "mailto", target: mailtoMatch[1]! };
  }
  return { available: false, method: "none", target: null };
}

export function normalizeOneClickTarget(input: unknown): string {
  if (typeof input !== "string") throw new Error("Unsubscribe target must be a string.");
  const value = input.trim();
  if (!value || value.length > MAX_TARGET_LENGTH) {
    throw new Error("Unsubscribe target is empty or too long.");
  }

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("Unsubscribe target is not a valid URL.");
  }

  if (url.protocol !== "https:") throw new Error("One-click unsubscribe requires HTTPS.");
  if (url.username || url.password) throw new Error("Unsubscribe target must not contain credentials.");
  if (url.port && url.port !== "443") throw new Error("Unsubscribe target must use the standard HTTPS port.");
  if (!url.hostname || url.hostname.endsWith(".local") || url.hostname === "localhost") {
    throw new Error("Unsubscribe target host is not allowed.");
  }
  url.hash = "";
  return url.toString();
}

function isPrivateIpv4(address: string): boolean {
  const octets = address.split(".").map(Number);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b] = octets;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 100 && b! >= 64 && b! <= 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b! >= 16 && b! <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a! >= 224) return true;
  return false;
}

function isPrivateIpv6(address: string): boolean {
  const value = address.toLowerCase().split("%")[0]!;
  if (value === "::" || value === "::1") return true;
  if (value.startsWith("fc") || value.startsWith("fd")) return true;
  if (/^fe[89ab]/.test(value)) return true;
  if (value.startsWith("ff")) return true;
  if (value.startsWith("2001:db8:")) return true;
  const mapped = value.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  return mapped ? isPrivateIpv4(mapped[1]!) : false;
}

export function isPublicNetworkAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !isPrivateIpv4(address);
  if (family === 6) return !isPrivateIpv6(address);
  return false;
}

async function resolvePinnedPublicAddress(hostname: string): Promise<{ address: string; family: 4 | 6 }> {
  if (isIP(hostname)) {
    if (!isPublicNetworkAddress(hostname)) throw new Error("Unsubscribe target resolves to a non-public address.");
    return { address: hostname, family: isIP(hostname) as 4 | 6 };
  }

  const answers = await lookup(hostname, { all: true, verbatim: true });
  const selected = answers.find((answer) => isPublicNetworkAddress(answer.address));
  if (!selected) throw new Error("Unsubscribe target did not resolve to a public address.");
  return { address: selected.address, family: selected.family as 4 | 6 };
}

/** Sends the exact RFC 8058 form body to a DNS-pinned public HTTPS endpoint.
 * Redirects are deliberately not followed because changing destinations or
 * methods would no longer be the message-authorized one-click action. */
export async function postRfc8058OneClick(target: string): Promise<OneClickPostResponse> {
  const normalized = normalizeOneClickTarget(target);
  const url = new URL(normalized);
  const pinned = await resolvePinnedPublicAddress(url.hostname);
  const body = Buffer.from(ONE_CLICK_BODY, "utf8");

  return await new Promise<OneClickPostResponse>((resolve, reject) => {
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(totalTimer);
      fn();
    };

    const req = request({
      protocol: "https:",
      hostname: url.hostname,
      port: 443,
      path: `${url.pathname}${url.search}`,
      method: "POST",
      servername: url.hostname,
      lookup: ((_hostname: string, _options: unknown, callback: (error: Error | null, address: string, family: number) => void) => {
        callback(null, pinned.address, pinned.family);
      }) as any,
      headers: {
        Host: url.host,
        "User-Agent": "EmailShieldUnsubscribe/1.0",
        Accept: "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": String(body.length),
      },
    } as any, (response) => {
      const status = response.statusCode ?? 0;
      response.resume();
      response.once("end", () => finish(() => resolve({ status })));
      response.once("error", (error) => finish(() => reject(error)));
    });

    const totalTimer = setTimeout(() => {
      req.destroy(new Error(`One-click unsubscribe exceeded ${REQUEST_TIMEOUT_MS}ms deadline.`));
    }, REQUEST_TIMEOUT_MS);

    req.once("error", (error) => finish(() => reject(error)));
    req.end(body);
  });
}

export async function executeOneClickUnsubscribe(
  target: string,
  postImpl: (url: string) => Promise<OneClickPostResponse> = postRfc8058OneClick,
): Promise<OneClickUnsubscribeResult> {
  let normalized: string;
  try {
    normalized = normalizeOneClickTarget(target);
  } catch (error) {
    return { success: false, reason: error instanceof Error ? error.message : String(error) };
  }

  try {
    const response = await postImpl(normalized);
    const success = response.status >= 200 && response.status < 300;
    return {
      success,
      status: response.status,
      reason: success ? undefined : `Unsubscribe endpoint returned HTTP ${response.status}.`,
    };
  } catch (error) {
    return { success: false, reason: error instanceof Error ? error.message : String(error) };
  }
}
