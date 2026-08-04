import { isIP } from "node:net";

const COMMON_MULTI_LABEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk",
  "com.pk", "net.pk", "org.pk",
  "co.jp", "ne.jp", "or.jp",
  "com.au", "net.au", "org.au",
  "co.nz", "com.sg", "com.my", "co.in",
  "com.br", "com.mx", "com.tr", "com.sa",
  "com.cn", "com.hk", "com.tw", "co.za",
]);

export function normalizeDomainName(domain: string): string {
  return domain.trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
}

export function organizationalDomain(domain: string): string {
  const normalized = normalizeDomainName(domain);
  if (!normalized || isIP(normalized)) return normalized;

  const labels = normalized.split(".").filter(Boolean);
  if (labels.length <= 2) return normalized;

  const finalTwo = labels.slice(-2).join(".");
  if (COMMON_MULTI_LABEL_SUFFIXES.has(finalTwo) && labels.length >= 3) {
    return labels.slice(-3).join(".");
  }
  return finalTwo;
}

export function sameOrganizationalDomain(first: string, second: string): boolean {
  const a = organizationalDomain(first);
  const b = organizationalDomain(second);
  return Boolean(a && b && a === b);
}

export function isKnownSenderRelay(domain: string): boolean {
  const normalized = normalizeDomainName(domain);
  return normalized === "privaterelay.appleid.com" || normalized.endsWith(".privaterelay.appleid.com");
}
