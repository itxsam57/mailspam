import { createHash } from "node:crypto";

export type ExposureCheckState = "exposed" | "not_found" | "unavailable";

export interface ExposureFinding {
  sourceId: string;
  firstObserved: string | null;
  categories: string[];
}

export interface IdentityExposureResult {
  schemaVersion: 1;
  state: ExposureCheckState;
  findings: ExposureFinding[];
  checkedAt: string;
  lookupPrivacy: "hash_prefix_only";
  limitations: string[];
}

export interface ExposurePrefixResponse {
  suffix: string;
  count: number;
  sourceId?: string;
  firstObserved?: string | null;
  categories?: string[];
}

export interface ExposureLookupPort {
  lookup(kind: "email_sha256" | "password_sha1", prefix: string, signal: AbortSignal): Promise<ExposurePrefixResponse[] | null>;
}

export class UnconfiguredExposureLookupPort implements ExposureLookupPort {
  async lookup(_kind: "email_sha256" | "password_sha1", _prefix: string, signal: AbortSignal): Promise<ExposurePrefixResponse[] | null> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    return null;
  }
}

const MAX_EXPOSURE_RESPONSE_BYTES = 256 * 1024;

/**
 * Optional production gateway adapter. The gateway receives only a short hash
 * prefix and returns candidate suffixes; plaintext email/password values never
 * leave the device. HTTP is permitted only on loopback acceptance endpoints.
 */
export class HttpExposureLookupPort implements ExposureLookupPort {
  private readonly baseUrl: string;

  constructor(baseUrl: string) {
    const parsed = new URL(baseUrl);
    if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && ["127.0.0.1", "localhost", "::1"].includes(parsed.hostname))) {
      throw new Error("Exposure lookup requires HTTPS except for loopback acceptance testing.");
    }
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    this.baseUrl = parsed.toString().replace(/\/$/, "");
  }

  async lookup(kind: "email_sha256" | "password_sha1", prefix: string, signal: AbortSignal): Promise<ExposurePrefixResponse[] | null> {
    const response = await fetch(`${this.baseUrl}/v1/exposure/${kind}/${encodeURIComponent(prefix)}`, {
      method: "GET",
      headers: { Accept: "application/json" },
      redirect: "error",
      cache: "no-store",
      signal: AbortSignal.any([signal, AbortSignal.timeout(12_000)]),
    });
    if (!response.ok) throw new Error(`Exposure service returned HTTP ${response.status}.`);
    const contentLength = Number(response.headers.get("content-length") ?? "0");
    if (Number.isFinite(contentLength) && contentLength > MAX_EXPOSURE_RESPONSE_BYTES) throw new Error("Exposure service response exceeded its resource limit.");
    const raw = await response.text();
    if (Buffer.byteLength(raw, "utf8") > MAX_EXPOSURE_RESPONSE_BYTES) throw new Error("Exposure service response exceeded its resource limit.");
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed) || parsed.length > 5_000) throw new Error("Exposure service response is invalid.");
    return parsed.map((entry) => normalizePrefixResponse(entry));
  }
}

function normalizePrefixResponse(input: unknown): ExposurePrefixResponse {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Exposure service response entry is invalid.");
  const value = input as Record<string, unknown>;
  if (Object.keys(value).some((key) => !["suffix", "count", "sourceId", "firstObserved", "categories"].includes(key))) throw new Error("Exposure service response entry is invalid.");
  if (typeof value.suffix !== "string" || !/^[A-F0-9]{8,64}$/i.test(value.suffix) || !Number.isSafeInteger(value.count) || Number(value.count) < 0) {
    throw new Error("Exposure service response entry is invalid.");
  }
  const categories = Array.isArray(value.categories)
    ? value.categories.filter((item): item is string => typeof item === "string" && item.length <= 64).slice(0, 20)
    : [];
  return {
    suffix: value.suffix.toUpperCase(),
    count: Number(value.count),
    sourceId: typeof value.sourceId === "string" ? value.sourceId.slice(0, 100) : undefined,
    firstObserved: typeof value.firstObserved === "string" ? value.firstObserved.slice(0, 64) : null,
    categories,
  };
}

function normalizeEmail(email: string): string {
  const normalized = email.trim().toLowerCase();
  if (normalized.length < 3 || normalized.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) throw new Error("Email address is invalid.");
  return normalized;
}

function hashParts(kind: "email_sha256" | "password_sha1", value: string): { prefix: string; suffix: string } {
  const hash = createHash(kind === "email_sha256" ? "sha256" : "sha1").update(value, "utf8").digest("hex").toUpperCase();
  const prefixLength = kind === "email_sha256" ? 10 : 5;
  return { prefix: hash.slice(0, prefixLength), suffix: hash.slice(prefixLength) };
}

async function checkHash(
  kind: "email_sha256" | "password_sha1",
  value: string,
  port: ExposureLookupPort,
  signal: AbortSignal,
): Promise<IdentityExposureResult> {
  const { prefix, suffix } = hashParts(kind, value);
  let candidates: ExposurePrefixResponse[] | null;
  try { candidates = await port.lookup(kind, prefix, signal); }
  catch (error) {
    return {
      schemaVersion: 1,
      state: "unavailable",
      findings: [],
      checkedAt: new Date().toISOString(),
      lookupPrivacy: "hash_prefix_only",
      limitations: [`Exposure lookup failed and was not interpreted as clean: ${error instanceof Error ? error.message : String(error)}`],
    };
  }
  if (candidates === null) {
    return {
      schemaVersion: 1,
      state: "unavailable",
      findings: [],
      checkedAt: new Date().toISOString(),
      lookupPrivacy: "hash_prefix_only",
      limitations: ["No vetted privacy-preserving exposure service is configured. Email Shield did not treat this as a clean exposure result."],
    };
  }
  const matches = candidates.filter((candidate) => candidate.suffix.toUpperCase() === suffix);
  const findings = matches.slice(0, 100).map((candidate): ExposureFinding => ({
    sourceId: candidate.sourceId || "exposure-source",
    firstObserved: candidate.firstObserved ?? null,
    categories: candidate.categories ?? [],
  }));
  return {
    schemaVersion: 1,
    state: findings.length || matches.some((candidate) => candidate.count > 0) ? "exposed" : "not_found",
    findings,
    checkedAt: new Date().toISOString(),
    lookupPrivacy: "hash_prefix_only",
    limitations: ["A not-found result means the configured exposure source did not return this hash. It does not prove the identity or credential has never been exposed elsewhere."],
  };
}

export function checkEmailExposure(email: string, port: ExposureLookupPort, signal = new AbortController().signal): Promise<IdentityExposureResult> {
  return checkHash("email_sha256", normalizeEmail(email), port, signal);
}

export function checkPasswordExposure(password: string, port: ExposureLookupPort, signal = new AbortController().signal): Promise<IdentityExposureResult> {
  if (typeof password !== "string" || password.length < 1 || password.length > 1024) throw new Error("Credential exposure check input is invalid.");
  return checkHash("password_sha1", password, port, signal);
}

export function familyExposureSummary(results: readonly IdentityExposureResult[]): {
  checkedMembers: number;
  exposedMembers: number;
  unavailableMembers: number;
  privacy: "counts_only_no_breach_detail";
} {
  return {
    checkedMembers: results.length,
    exposedMembers: results.filter((result) => result.state === "exposed").length,
    unavailableMembers: results.filter((result) => result.state === "unavailable").length,
    privacy: "counts_only_no_breach_detail",
  };
}
