import type { ListHeaders } from "../canonical/envelope.js";
import { normalizeDomainName } from "./domainRelation.js";

const MAX_RAW_HEADER_BYTES = 128 * 1024;
const MAX_DKIM_SIGNATURE_HEADERS = 16;
const MAX_UNFOLDED_DKIM_SIGNATURE_CHARS = 16 * 1024;
const MAX_SELECTOR_CHARS = 253;
const REQUIRED_ONE_CLICK_HEADERS = new Set(["list-unsubscribe", "list-unsubscribe-post"]);

function boundedRawHeaderSection(raw: string | Buffer): string | null {
  const source = Buffer.isBuffer(raw) ? raw : Buffer.from(raw, "utf8");
  const bounded = source.subarray(0, Math.min(source.length, MAX_RAW_HEADER_BYTES));
  const text = bounded.toString("utf8");
  const crlfBoundary = text.indexOf("\r\n\r\n");
  const lfBoundary = text.indexOf("\n\n");
  const boundary = crlfBoundary >= 0
    ? crlfBoundary
    : lfBoundary >= 0
      ? lfBoundary
      : -1;
  if (boundary < 0) return null;
  return text.slice(0, boundary);
}

function unfoldHeaders(section: string): string[] {
  const lines = section.split(/\r?\n/);
  const headers: string[] = [];
  let current = "";
  for (const line of lines) {
    if (/^[ \t]/.test(line)) {
      if (current) current += ` ${line.trim()}`;
      continue;
    }
    if (current) headers.push(current);
    current = line;
  }
  if (current) headers.push(current);
  return headers;
}

function parseTagList(value: string): Map<string, string> {
  const tags = new Map<string, string>();
  for (const part of value.split(";")) {
    const separator = part.indexOf("=");
    if (separator <= 0) continue;
    const name = part.slice(0, separator).trim().toLowerCase();
    const tagValue = part.slice(separator + 1).trim();
    if (!name || tags.has(name)) continue;
    tags.set(name, tagValue);
  }
  return tags;
}

function normalizeSelector(raw: string | undefined): string | null {
  const selector = (raw ?? "").trim().toLowerCase();
  if (!selector || selector.length > MAX_SELECTOR_CHARS) return null;
  if (!/^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/i.test(selector)) return null;
  return selector;
}

/**
 * Extracts only the minimal DKIM identity metadata needed to prove RFC 8058
 * header coverage. It does not verify DKIM cryptography; cryptographic validity
 * is supplied separately by a trusted Authentication-Results `dkim=pass`.
 * Duplicate domain+selector entries are intentionally preserved so a caller can
 * reject ambiguous correlation rather than silently choosing one signature.
 */
export function extractOneClickDkimCoverage(raw: string | Buffer): NonNullable<ListHeaders["oneClickDkimCoverage"]> {
  const section = boundedRawHeaderSection(raw);
  if (!section) return [];

  const coverage: NonNullable<ListHeaders["oneClickDkimCoverage"]> = [];
  let seenSignatures = 0;
  for (const header of unfoldHeaders(section)) {
    const match = header.match(/^DKIM-Signature\s*:\s*([\s\S]*)$/i);
    if (!match) continue;
    seenSignatures += 1;
    if (seenSignatures > MAX_DKIM_SIGNATURE_HEADERS) break;

    const value = match[1] ?? "";
    if (!value || value.length > MAX_UNFOLDED_DKIM_SIGNATURE_CHARS) continue;
    const tags = parseTagList(value);
    const domain = normalizeDomainName(tags.get("d") ?? "");
    const selector = normalizeSelector(tags.get("s"));
    if (!domain || !domain.includes(".") || !selector) continue;

    const signedHeaders = new Set(
      (tags.get("h") ?? "")
        .split(":")
        .map((name) => name.trim().toLowerCase())
        .filter(Boolean),
    );
    if (![...REQUIRED_ONE_CLICK_HEADERS].every((name) => signedHeaders.has(name))) continue;
    coverage.push({ domain, selector });
  }
  return coverage;
}
