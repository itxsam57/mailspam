import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  openSync,
  closeSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import type { AuthenticationSignals, Provider } from "../canonical/envelope.js";
import { FixtureAdapter } from "../adapters/fixtures/fixtureAdapter.js";
import { InMemoryPersonalPolicyStore } from "../engine/layers/personalRules.js";
import { scanMessageThroughPortableCore } from "../core/portableCore.js";

export const REGRESSION_VAULT_SCHEMA_VERSION = 1 as const;
export const REGRESSION_VAULT_SANITIZER_VERSION = 1 as const;
export const MAX_REGRESSION_SAMPLE_BYTES = 512 * 1024;
const MAX_VAULT_ENTRIES = 2_048;
const PROVIDERS: Provider[] = ["gmail", "icloud", "outlook", "yahoo", "imap"];
const PRIVATE_HEADERS = new Set([
  "from", "to", "cc", "bcc", "reply-to", "sender", "return-path", "delivered-to",
  "received", "message-id", "in-reply-to", "references", "x-original-to", "x-envelope-to",
]);

export type RegressionExpectedVerdict = "safe" | "non_safe";
export type RegressionSampleKind = "malicious" | "legit";
export type RegressionReviewerRole = "security_reviewer" | "quality_reviewer";

export interface RegressionCandidate {
  schemaVersion: 1;
  sanitizerVersion: 1;
  candidateId: string;
  category: string;
  kind: RegressionSampleKind;
  expectedVerdict: RegressionExpectedVerdict;
  authenticationTrust: "trusted" | "unknown";
  sanitizedSha256: string;
  sanitizedBytes: number;
  attestation: "operator_review_required_no_private_content";
}

export interface RegressionVaultEntry {
  id: string;
  category: string;
  kind: RegressionSampleKind;
  expectedVerdict: RegressionExpectedVerdict;
  authenticationTrust: "trusted" | "unknown";
  file: string;
  sha256: string;
  provenance: {
    source: "verified_anonymized_operator_sample";
    sanitizerVersion: 1;
    reviewDigest: string;
    reviewerRole: RegressionReviewerRole;
  };
}

export interface RegressionVaultManifest {
  schemaVersion: 1;
  entries: RegressionVaultEntry[];
}

function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function validCategory(value: string): boolean {
  return /^[a-z][a-z0-9_]{2,63}$/.test(value);
}

function exactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function sanitizeText(value: string): string {
  let result = value.replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "person@sample.invalid");
  result = result.replace(/(?<![A-Za-z0-9])(?:\+?\d[\d ().-]{7,}\d)(?![A-Za-z0-9])/g, "[redacted-phone]");
  result = result.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, "192.0.2.1");
  result = result.replace(/https?:\/\/[^\s<>"']+/gi, (raw) => {
    const trailing = raw.match(/[),.;!?]+$/)?.[0] ?? "";
    const candidate = trailing ? raw.slice(0, -trailing.length) : raw;
    try {
      const url = new URL(candidate);
      url.username = "";
      url.password = "";
      url.hostname = "unsafe.example";
      url.port = "";
      return `${url.toString()}${trailing}`;
    } catch {
      return `https://unsafe.example/${trailing}`;
    }
  });
  return result;
}

/**
 * Deterministically removes routing/identity headers and masks direct contact,
 * IP, phone and destination identifiers. Human approval remains mandatory
 * because free-form prose cannot be proven free of personal names by software.
 */
export function sanitizeRegressionSample(rawEml: string): string {
  if (Buffer.byteLength(rawEml, "utf8") > MAX_REGRESSION_SAMPLE_BYTES) {
    throw new Error(`Regression sample exceeds ${MAX_REGRESSION_SAMPLE_BYTES} bytes.`);
  }
  if (rawEml.includes("\0")) throw new Error("Regression sample contains a NUL byte.");
  const normalized = rawEml.replace(/\r\n?/g, "\n");
  const boundary = normalized.indexOf("\n\n");
  if (boundary < 1) throw new Error("Regression sample must contain RFC 5322 headers and a body.");
  const headerLines = normalized.slice(0, boundary).split("\n");
  const retained: string[] = [];
  let discardContinuation = false;
  for (const line of headerLines) {
    if (/^[ \t]/.test(line)) {
      if (!discardContinuation) retained.push(sanitizeText(line));
      continue;
    }
    const match = /^([^:]+):/.exec(line);
    if (!match) throw new Error("Regression sample contains a malformed header line.");
    discardContinuation = PRIVATE_HEADERS.has(match[1]!.trim().toLowerCase());
    if (!discardContinuation) retained.push(sanitizeText(line));
  }
  const body = sanitizeText(normalized.slice(boundary + 2));
  return [
    "From: Security Sample <sender@sample.invalid>",
    "To: Review Fixture <review@sample.invalid>",
    "Message-ID: <regression-sample@sample.invalid>",
    ...retained.filter((line) => !/^(?:from|to|message-id):/i.test(line)),
    "",
    body,
  ].join("\n").replace(/\n*$/, "\n");
}

export function assertSanitizedRegressionSample(value: string): void {
  if (Buffer.byteLength(value, "utf8") > MAX_REGRESSION_SAMPLE_BYTES) throw new Error("Sanitized sample is oversized.");
  const allowedAddresses = new Set(["sender@sample.invalid", "review@sample.invalid", "regression-sample@sample.invalid", "person@sample.invalid"]);
  const addresses = value.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi) ?? [];
  if (addresses.some((address) => !allowedAddresses.has(address.toLowerCase()))) {
    throw new Error("Sanitized sample still contains a non-placeholder email address.");
  }
  if (/^\s*(?:received|return-path|delivered-to|cc|bcc|reply-to|references|in-reply-to)\s*:/im.test(value)) {
    throw new Error("Sanitized sample still contains a private routing or identity header.");
  }
  const urls = value.match(/https?:\/\/[^\s<>"']+/gi) ?? [];
  for (const raw of urls) {
    let url: URL;
    try { url = new URL(raw.replace(/[),.;!?]+$/, "")); }
    catch { throw new Error("Sanitized sample contains an invalid URL."); }
    if (url.hostname !== "unsafe.example") throw new Error("Sanitized sample contains a non-placeholder destination host.");
  }
}

function writeExclusive(path: string, value: string): void {
  mkdirSync(dirname(path), { recursive: true });
  const fd = openSync(path, "wx", 0o600);
  try { writeFileSync(fd, value, { encoding: "utf8" }); }
  finally { closeSync(fd); }
}

export function intakeRegressionSample(options: {
  candidateRoot: string;
  rawEml: string;
  category: string;
  kind: RegressionSampleKind;
  expectedVerdict: RegressionExpectedVerdict;
  authenticationTrust: AuthenticationSignals["providerTrust"];
  attestedNoPrivateContent: boolean;
}): RegressionCandidate {
  if (!options.attestedNoPrivateContent) throw new Error("Intake requires --attest-no-private-content after operator review.");
  if (!validCategory(options.category)) throw new Error("Category must be 3-64 lowercase letters, digits or underscores.");
  if (!(["malicious", "legit"] as const).includes(options.kind)) throw new Error("Sample kind is invalid.");
  if (!(["safe", "non_safe"] as const).includes(options.expectedVerdict)) throw new Error("Expected verdict is invalid.");
  if (options.authenticationTrust !== "trusted" && options.authenticationTrust !== "unknown") throw new Error("Authentication trust must be trusted or unknown.");
  if ((options.kind === "malicious") !== (options.expectedVerdict === "non_safe")) {
    throw new Error("Malicious samples must expect non_safe and legitimate controls must expect safe.");
  }
  const sanitized = sanitizeRegressionSample(options.rawEml);
  assertSanitizedRegressionSample(sanitized);
  const digest = sha256(sanitized);
  const candidateId = digest.slice(0, 32);
  const directory = resolve(options.candidateRoot, candidateId);
  const candidate: RegressionCandidate = {
    schemaVersion: 1,
    sanitizerVersion: REGRESSION_VAULT_SANITIZER_VERSION,
    candidateId,
    category: options.category,
    kind: options.kind,
    expectedVerdict: options.expectedVerdict,
    authenticationTrust: options.authenticationTrust,
    sanitizedSha256: digest,
    sanitizedBytes: Buffer.byteLength(sanitized, "utf8"),
    attestation: "operator_review_required_no_private_content",
  };
  writeExclusive(join(directory, "sample.eml"), sanitized);
  try { writeExclusive(join(directory, "candidate.json"), `${JSON.stringify(candidate, null, 2)}\n`); }
  catch (error) { unlinkSync(join(directory, "sample.eml")); throw error; }
  writeExclusive(join(directory, "REVIEW.txt"), [
    "Review the sanitized sample for residual personal/private content and preserved scam semantics.",
    `Candidate: ${candidateId}`,
    `Review digest: ${digest}`,
    "Approval requires this exact digest and an authorized reviewer role.",
    "",
  ].join("\n"));
  return candidate;
}

function assertCandidate(value: unknown): asserts value is RegressionCandidate {
  if (!isRecord(value) || !exactKeys(value, [
    "schemaVersion", "sanitizerVersion", "candidateId", "category", "kind", "expectedVerdict",
    "authenticationTrust", "sanitizedSha256", "sanitizedBytes", "attestation",
  ])) throw new Error("Regression candidate schema is invalid.");
  if (value.schemaVersion !== 1 || value.sanitizerVersion !== 1 || !validCategory(String(value.category))) throw new Error("Regression candidate version/category is invalid.");
  if (!/^[a-f0-9]{32}$/.test(String(value.candidateId)) || !/^[a-f0-9]{64}$/.test(String(value.sanitizedSha256))) throw new Error("Regression candidate digest is invalid.");
  if (!Number.isSafeInteger(value.sanitizedBytes) || Number(value.sanitizedBytes) < 1 || Number(value.sanitizedBytes) > MAX_REGRESSION_SAMPLE_BYTES) throw new Error("Regression candidate byte count is invalid.");
  if (!(["malicious", "legit"] as const).includes(value.kind as RegressionSampleKind)) throw new Error("Regression candidate kind is invalid.");
  if (!(["safe", "non_safe"] as const).includes(value.expectedVerdict as RegressionExpectedVerdict)) throw new Error("Regression candidate expectation is invalid.");
  if (value.authenticationTrust !== "trusted" && value.authenticationTrust !== "unknown") throw new Error("Regression candidate authentication trust is invalid.");
  if (value.attestation !== "operator_review_required_no_private_content") throw new Error("Regression candidate attestation is invalid.");
}

export function assertRegressionVaultManifest(value: unknown): asserts value is RegressionVaultManifest {
  if (!isRecord(value) || !exactKeys(value, ["schemaVersion", "entries"]) || value.schemaVersion !== 1 || !Array.isArray(value.entries) || value.entries.length > MAX_VAULT_ENTRIES) {
    throw new Error("Regression Vault manifest schema is invalid.");
  }
  const ids = new Set<string>();
  const digests = new Set<string>();
  let previous = "";
  for (const item of value.entries) {
    if (!isRecord(item) || !exactKeys(item, ["id", "category", "kind", "expectedVerdict", "authenticationTrust", "file", "sha256", "provenance"])) throw new Error("Regression Vault entry schema is invalid.");
    if (!/^[a-f0-9]{32}$/.test(String(item.id)) || !validCategory(String(item.category)) || !/^[a-f0-9]{64}$/.test(String(item.sha256))) throw new Error("Regression Vault entry identity is invalid.");
    if (!(["malicious", "legit"] as const).includes(item.kind as RegressionSampleKind) || !(["safe", "non_safe"] as const).includes(item.expectedVerdict as RegressionExpectedVerdict)) throw new Error("Regression Vault entry expectation is invalid.");
    if (item.authenticationTrust !== "trusted" && item.authenticationTrust !== "unknown") throw new Error("Regression Vault authentication trust is invalid.");
    if (typeof item.file !== "string" || !/^samples\/[a-z][a-z0-9_]{2,63}\/[a-f0-9]{32}\.eml$/.test(item.file)) throw new Error("Regression Vault entry path is invalid.");
    if (!isRecord(item.provenance) || !exactKeys(item.provenance, ["source", "sanitizerVersion", "reviewDigest", "reviewerRole"])) throw new Error("Regression Vault provenance is invalid.");
    if (item.provenance.source !== "verified_anonymized_operator_sample" || item.provenance.sanitizerVersion !== 1 || item.provenance.reviewDigest !== item.sha256 || !(["security_reviewer", "quality_reviewer"] as const).includes(item.provenance.reviewerRole as RegressionReviewerRole)) throw new Error("Regression Vault review provenance is invalid.");
    if (ids.has(String(item.id)) || digests.has(String(item.sha256))) throw new Error("Regression Vault contains a duplicate sample.");
    if (String(item.id) < previous) throw new Error("Regression Vault entries must be sorted by id.");
    ids.add(String(item.id)); digests.add(String(item.sha256)); previous = String(item.id);
  }
}

export async function evaluateRegressionSample(
  rawEml: string,
  expected: RegressionExpectedVerdict,
  authenticationTrust: "trusted" | "unknown",
): Promise<Record<Provider, string>> {
  const outcomes = {} as Record<Provider, string>;
  for (const provider of PROVIDERS) {
    const adapter = new FixtureAdapter(provider, [{
      id: `vault-${provider}`,
      rawEml,
      folder: "inbox",
      providerFolderName: "INBOX",
      authenticationTrust,
    }]);
    const controller = new AbortController();
    try {
      await adapter.connect(controller.signal);
      const inbox = (await adapter.listFolders(controller.signal)).find((folder) => folder.normalized === "inbox");
      if (!inbox) throw new Error(`${provider} fixture did not expose Inbox.`);
      const page = await adapter.fetchPage(inbox, null, 1, controller.signal);
      if (page.envelopes.length !== 1) throw new Error(`${provider} fixture did not return exactly one sample.`);
      const result = scanMessageThroughPortableCore(page.envelopes[0]!, new InMemoryPersonalPolicyStore(), []);
      outcomes[provider] = result.scored.verdict;
      const matches = expected === "safe" ? result.scored.verdict === "safe" : result.scored.verdict !== "safe";
      if (!matches) throw new Error(`Regression sample expected ${expected} but ${provider} returned ${result.scored.verdict}.`);
    } finally {
      await adapter.disconnect();
    }
  }
  return outcomes;
}

function readManifest(vaultRoot: string): RegressionVaultManifest {
  const path = join(vaultRoot, "manifest.json");
  if (!existsSync(path)) return { schemaVersion: 1, entries: [] };
  const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
  assertRegressionVaultManifest(parsed);
  return parsed;
}

function safeChild(root: string, relative: string): string {
  const absoluteRoot = resolve(root);
  const target = resolve(absoluteRoot, relative);
  if (!target.startsWith(`${absoluteRoot}${sep}`)) throw new Error("Regression Vault path escapes its root.");
  return target;
}

function atomicManifest(path: string, manifest: RegressionVaultManifest): void {
  const temporary = `${path}.${process.pid}.tmp`;
  writeExclusive(temporary, `${JSON.stringify(manifest, null, 2)}\n`);
  try { renameSync(temporary, path); }
  catch (error) { if (existsSync(temporary)) unlinkSync(temporary); throw error; }
}

export async function approveRegressionCandidate(options: {
  candidateRoot: string;
  candidateId: string;
  reviewDigest: string;
  reviewerRole: RegressionReviewerRole;
  vaultRoot: string;
}): Promise<{ entry: RegressionVaultEntry; outcomes: Record<Provider, string> }> {
  if (!/^[a-f0-9]{32}$/.test(options.candidateId)) throw new Error("Candidate ID is invalid.");
  if (!/^[a-f0-9]{64}$/.test(options.reviewDigest)) throw new Error("Review digest is invalid.");
  if (!(["security_reviewer", "quality_reviewer"] as const).includes(options.reviewerRole)) throw new Error("Reviewer role is invalid.");
  const directory = safeChild(options.candidateRoot, options.candidateId);
  const candidateValue: unknown = JSON.parse(readFileSync(join(directory, "candidate.json"), "utf8"));
  assertCandidate(candidateValue);
  const sample = readFileSync(join(directory, "sample.eml"), "utf8");
  assertSanitizedRegressionSample(sample);
  const digest = sha256(sample);
  if (candidateValue.candidateId !== options.candidateId || candidateValue.sanitizedSha256 !== digest || candidateValue.sanitizedBytes !== Buffer.byteLength(sample, "utf8")) throw new Error("Regression candidate content does not match its intake record.");
  if (options.reviewDigest !== digest) throw new Error("Review digest does not match the sanitized candidate.");
  const outcomes = await evaluateRegressionSample(sample, candidateValue.expectedVerdict, candidateValue.authenticationTrust);
  const manifest = readManifest(options.vaultRoot);
  if (manifest.entries.some((entry) => entry.id === options.candidateId || entry.sha256 === digest)) throw new Error("Regression Vault already contains this sample.");
  const relative = `samples/${candidateValue.category}/${candidateValue.candidateId}.eml`;
  const entry: RegressionVaultEntry = {
    id: candidateValue.candidateId,
    category: candidateValue.category,
    kind: candidateValue.kind,
    expectedVerdict: candidateValue.expectedVerdict,
    authenticationTrust: candidateValue.authenticationTrust,
    file: relative,
    sha256: digest,
    provenance: {
      source: "verified_anonymized_operator_sample",
      sanitizerVersion: 1,
      reviewDigest: digest,
      reviewerRole: options.reviewerRole,
    },
  };
  writeExclusive(safeChild(options.vaultRoot, relative), sample);
  try {
    manifest.entries.push(entry);
    manifest.entries.sort((left, right) => left.id.localeCompare(right.id));
    assertRegressionVaultManifest(manifest);
    atomicManifest(join(resolve(options.vaultRoot), "manifest.json"), manifest);
  } catch (error) {
    unlinkSync(safeChild(options.vaultRoot, relative));
    throw error;
  }
  return { entry, outcomes };
}

export async function verifyRegressionVault(vaultRoot: string): Promise<Array<{ id: string; outcomes: Record<Provider, string> }>> {
  const manifest = readManifest(vaultRoot);
  if (manifest.entries.length < 1) throw new Error("Regression Vault must contain at least one approved sample.");
  const results = [];
  for (const entry of manifest.entries) {
    const sample = readFileSync(safeChild(vaultRoot, entry.file), "utf8");
    assertSanitizedRegressionSample(sample);
    if (sha256(sample) !== entry.sha256) throw new Error(`Regression Vault sample ${entry.id} failed SHA-256 verification.`);
    results.push({
      id: entry.id,
      outcomes: await evaluateRegressionSample(sample, entry.expectedVerdict, entry.authenticationTrust),
    });
  }
  return results;
}
