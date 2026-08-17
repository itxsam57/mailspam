import { lookup } from "node:dns/promises";
import { request } from "node:https";
import type { IncomingMessage } from "node:http";
import { isIP } from "node:net";
import type { CanonicalEnvelope, LinkInfo } from "../canonical/envelope.js";
import { trustedPassingDkimIdentities } from "../engine/identitySignals.js";

export type UnsubscribeMethod = "one_click_post" | "mailto" | "link_only" | "none";

export interface UnsubscribeCapability {
  available: boolean;
  method: UnsubscribeMethod;
  target: string | null;
  source: "list_header" | "message_footer" | "none";
}

export interface OneClickUnsubscribeResult {
  success: boolean;
  status?: number;
  reason?: string;
}

export interface OneClickPostResponse { status: number }

const ONE_CLICK_BODY = "List-Unsubscribe=One-Click";
const MAX_TARGET_LENGTH = 4096;
const REQUEST_TIMEOUT_MS = 10_000;
const UNSUBSCRIBE_TEXT = /\b(?:unsubscribe|opt[ -]?out|stop emails?|email preferences?|manage (?:email )?preferences?|subscription settings)\b/i;
const UNSUBSCRIBE_URL_HINT = /(?:^|[\/_?&.=-])(?:unsubscribe|unsub|opt[._-]?out|email[._-]?preferences?|manage[._-]?(?:email[._-]?)?preferences?|subscription[._-]?(?:settings|preferences)?)(?:$|[\/_?&.=-])/i;

function headerTargets(raw: string | null): string[] {
  if (!raw) return [];
  const angleValues = [...raw.matchAll(/<([^>]+)>/g)].map((match) => match[1]!.trim());
  if (angleValues.length) return angleValues;
  return raw.split(",").map((value) => value.trim()).filter(Boolean);
}

function footerCandidate(link: LinkInfo): { method: "link_only" | "mailto"; target: string } | null {
  const target = (link.normalizedUrl || link.rawUrl || "").trim();
  const textDeclaresUnsubscribe = UNSUBSCRIBE_TEXT.test(link.visibleText ?? "");
  let urlDeclaresUnsubscribe = false;
  try {
    const parsed = new URL(target);
    const structuralHint = `${parsed.pathname}${parsed.search}`;
    urlDeclaresUnsubscribe = UNSUBSCRIBE_URL_HINT.test(structuralHint);
  } catch {}
  if (!textDeclaresUnsubscribe && !urlDeclaresUnsubscribe) return null;
  if (/^https:\/\//i.test(target)) return { method: "link_only", target };
  if (/^mailto:/i.test(target)) return { method: "mailto", target };
  return null;
}

function normalizedFooterTarget(envelope: CanonicalEnvelope): { method: "link_only" | "mailto"; target: string } | null {
  for (const link of envelope.links) {
    const candidate = footerCandidate(link);
    if (candidate) return candidate;
  }
  return null;
}

function oneClickDkimAuthorized(envelope: CanonicalEnvelope): boolean {
  if (!envelope.listHeaders.oneClickHeaderSetUnambiguous) return false;
  const signatures = envelope.listHeaders.oneClickDkimSignatures ?? [];
  if (signatures.length === 0) return false;

  for (const identity of trustedPassingDkimIdentities(envelope)) {
    const matches = signatures.filter((item) => item.domain === identity.domain && item.selector === identity.selector);
    if (matches.length === 1 && matches[0]!.coversRequiredHeaders) return true;
  }
  return false;
}

/**
 * Every canonical provider uses this same capability resolver. RFC 8058
 * one-click POST is offered only when the raw list-header field set is
 * unambiguous and a trusted passing DKIM identity maps unambiguously to exactly
 * one raw DKIM signature that signs both required list headers. A declared
 * one-click HTTPS target is never reinterpreted as a browser GET destination
 * when that authorization fails; only an independent mailto/footer target may
 * remain available for explicit manual use.
 *
 * Manual footer discovery accepts either explicit unsubscribe text or a clear
 * unsubscribe/preferences URL structure. It never executes the target during
 * classification; the action still passes bounded HTTPS/mail validation at
 * registration/use time, so attacker-controlled message HTML cannot become an
 * insecure navigation or SSRF primitive.
 */
export function unsubscribeCapability(envelope: CanonicalEnvelope): UnsubscribeCapability {
  const targets = headerTargets(envelope.listHeaders.listUnsubscribe);
  const oneClickDeclared = /list-unsubscribe\s*=\s*one-click/i.test(
    envelope.listHeaders.listUnsubscribePost ?? "",
  );

  const httpsTarget = targets.find((target) => /^https:\/\//i.test(target));
  const mailtoTarget = targets.find((target) => /^mailto:/i.test(target));

  if (oneClickDeclared) {
    if (httpsTarget && oneClickDkimAuthorized(envelope)) {
      return { available: true, method: "one_click_post", target: httpsTarget, source: "list_header" };
    }
    if (mailtoTarget) {
      return { available: true, method: "mailto", target: mailtoTarget, source: "list_header" };
    }
    const footerTarget = normalizedFooterTarget(envelope);
    if (footerTarget) {
      return { available: true, method: footerTarget.method, target: footerTarget.target, source: "message_footer" };
    }
    return { available: false, method: "none", target: null, source: "none" };
  }

  if (httpsTarget) {
    return { available: true, method: "link_only", target: httpsTarget, source: "list_header" };
  }
  if (mailtoTarget) {
    return { available: true, method: "mailto", target: mailtoTarget, source: "list_header" };
  }

  const footerTarget = normalizedFooterTarget(envelope);
  if (footerTarget) {
    return { available: true, method: footerTarget.method, target: footerTarget.target, source: "message_footer" };
  }

  return { available: false, method: "none", target: null, source: "none" };
}

function normalizeWebTarget(input: unknown, automatic: boolean): string {
  if (typeof input !== "string") throw new Error("Unsubscribe target must be a string.");
  const value = input.trim();
  if (!value || value.length > MAX_TARGET_LENGTH) throw new Error("Unsubscribe target is empty or too long.");

  let url: URL;
  try { url = new URL(value); }
  catch { throw new Error("Unsubscribe target is not a valid URL."); }

  if (url.protocol !== "https:") {
    throw new Error(automatic ? "One-click unsubscribe requires HTTPS." : "Unsubscribe page must use HTTPS.");
  }
  if (url.username || url.password) throw new Error("Unsubscribe target must not contain credentials.");
  if (url.port && url.port !== "443") {
    throw new Error(automatic
      ? "One-click unsubscribe must use the standard HTTPS port."
      : "Unsubscribe page must use the standard HTTPS port.");
  }
  if (!url.hostname || url.hostname === "localhost" || url.hostname.endsWith(".local")) {
    throw new Error("Unsubscribe target host is not allowed.");
  }
  if (isIP(url.hostname) && !isPublicNetworkAddress(url.hostname)) {
    throw new Error("Unsubscribe target points to a non-public address.");
  }
  url.hash = "";
  return url.toString();
}

export function normalizeOneClickTarget(input: unknown): string {
  return normalizeWebTarget(input, true);
}

export function normalizeManualUnsubscribeTarget(method: "link_only" | "mailto", input: unknown): string {
  if (method === "link_only") return normalizeWebTarget(input, false);
  if (typeof input !== "string") throw new Error("Mail unsubscribe target must be a string.");
  const value = input.trim();
  if (!value || value.length > MAX_TARGET_LENGTH || /[\r\n]/.test(value)) {
    throw new Error("Mail unsubscribe target is invalid.");
  }
  let url: URL;
  try { url = new URL(value); }
  catch { throw new Error("Mail unsubscribe target is invalid."); }
  if (url.protocol !== "mailto:" || !url.pathname.includes("@")) {
    throw new Error("Mail unsubscribe target is invalid.");
  }
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
  if (value.startsWith("ff") || value.startsWith("2001:db8:")) return true;
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

export async function postRfc8058OneClick(target: string): Promise<OneClickPostResponse> {
  const normalized = normalizeOneClickTarget(target);
  const url = new URL(normalized);
  const pinned = await resolvePinnedPublicAddress(url.hostname);
  const body = Buffer.from(ONE_CLICK_BODY, "utf8");

  return await new Promise<OneClickPostResponse>((resolve, reject) => {
    let settled = false;
    let totalTimer: NodeJS.Timeout | undefined;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      if (totalTimer) clearTimeout(totalTimer);
      fn();
    };

    const req = request({
      protocol: "https:",
      hostname: url.hostname,
      port: 443,
      path: `${url.pathname}${url.search}`,
      method: "POST",
      servername: url.hostname,
      lookup: ((_hostname: string, _options: unknown, callback: (error: Error | null, address: string, family: number) => void) => callback(null, pinned.address, pinned.family)) as any,
      headers: {
        Host: url.host,
        "User-Agent": "EmailShieldUnsubscribe/1.0",
        Accept: "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": String(body.length),
      },
    } as any, (response: IncomingMessage) => {
      const status = response.statusCode ?? 0;
      response.resume();
      response.once("end", () => finish(() => resolve({ status })));
      response.once("error", (error) => finish(() => reject(error)));
    });

    totalTimer = setTimeout(() => req.destroy(new Error(`One-click unsubscribe exceeded ${REQUEST_TIMEOUT_MS}ms deadline.`)), REQUEST_TIMEOUT_MS);
    req.once("error", (error) => finish(() => reject(error)));
    req.end(body);
  });
}

export async function executeOneClickUnsubscribe(
  target: string,
  postImpl: (url: string) => Promise<OneClickPostResponse> = postRfc8058OneClick,
): Promise<OneClickUnsubscribeResult> {
  let normalized: string;
  try { normalized = normalizeOneClickTarget(target); }
  catch (error) { return { success: false, reason: error instanceof Error ? error.message : String(error) }; }

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
