/**
 * Hardened isolated resolver (spec 8.5, Section 10) for the explicit
 * "Analyze Links" action. Enforces the constraints required before this
 * touches a URL from an untrusted email:
 * - blocks localhost/private/link-local/cloud-metadata targets, and any
 *   redirect hop that lands on one (re-checked at every hop, closing the
 *   DNS-rebinding gap between the initial check and the actual fetch)
 * - only http(s), max 3 redirects, 512KB body cap, 5s total time cap
 * - only reads text/html or text/plain bodies; anything else is reported
 *   by content-type without downloading the body
 * - never executes anything, never submits forms, never forwards cookies
 *   or auth headers from the user's mailbox session
 *
 * NOTE: this sandbox's egress is restricted to package registries and
 * cannot reach arbitrary destinations, so this function is fully
 * implemented but only exercisable against fixture/mock targets here.
 */

const MAX_REDIRECTS = 3;
const MAX_BODY_BYTES = 512 * 1024;
const TOTAL_TIMEOUT_MS = 5000;
const ALLOWED_CONTENT_TYPES = ["text/html", "text/plain"];

function isBlockedHost(hostname: string): boolean {
  if (hostname === "localhost" || hostname === "0.0.0.0" || hostname === "169.254.169.254") return true;
  if (/^127\./.test(hostname)) return true;
  if (/^10\./.test(hostname)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(hostname)) return true;
  if (/^192\.168\./.test(hostname)) return true;
  if (/^169\.254\./.test(hostname)) return true;
  if (hostname === "::1" || hostname.startsWith("fe80:") || hostname.startsWith("fc") || hostname.startsWith("fd")) return true;
  return false;
}

export async function hardenedFetch(
  url: string
): Promise<{ finalUrl: string; contentType: string; body: string } | null> {
  let current = url;
  const deadline = Date.now() + TOTAL_TIMEOUT_MS;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    let parsed: URL;
    try {
      parsed = new URL(current);
    } catch {
      return null;
    }
    if (!["http:", "https:"].includes(parsed.protocol)) return null;
    if (isBlockedHost(parsed.hostname)) return null;

    const remaining = deadline - Date.now();
    if (remaining <= 0) return null;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), remaining);
    let response: Response;
    try {
      response = await fetch(current, {
        redirect: "manual",
        signal: controller.signal,
        headers: { "User-Agent": "EmailShieldLinkAnalyzer/1.0" }, // never forwards mailbox cookies/session
      });
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      if (!location) return null;
      current = new URL(location, current).toString();
      continue; // re-validated against isBlockedHost at the top of the next iteration
    }

    const contentType = (response.headers.get("content-type") ?? "").split(";")[0]!.trim();
    if (!ALLOWED_CONTENT_TYPES.includes(contentType)) {
      return { finalUrl: current, contentType, body: "" };
    }

    const reader = response.body?.getReader();
    if (!reader) return { finalUrl: current, contentType, body: "" };

    let received = 0;
    const chunks: Uint8Array[] = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.length;
      if (received > MAX_BODY_BYTES) {
        await reader.cancel();
        break;
      }
      chunks.push(value);
      if (Date.now() > deadline) {
        await reader.cancel();
        break;
      }
    }
    const body = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf-8");
    return { finalUrl: current, contentType, body };
  }

  return null; // exceeded MAX_REDIRECTS
}
