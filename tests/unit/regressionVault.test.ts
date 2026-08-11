import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  approveRegressionCandidate,
  assertRegressionVaultManifest,
  intakeRegressionSample,
  sanitizeRegressionSample,
  verifyRegressionVault,
} from "../../server/src/devtools/regressionVault.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function temporaryRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "email-shield-regression-vault-test-"));
  roots.push(root);
  return root;
}

const PRIVATE_SAMPLE = [
  "Received: from 203.0.113.77 by internal.example",
  "From: Private Person <private.person@real-company.test>",
  "To: Customer <customer@home.test>",
  "Reply-To: callback@real-company.test",
  "Message-ID: <private-id@real-company.test>",
  "Subject: Urgent password reset for private.person@real-company.test",
  "Content-Type: text/html; charset=utf-8",
  "",
  "Call +1 (555) 555-1234, then enter your password at https://private-login.test/reset.",
  "<form action=\"https://private-login.test/submit\"><input type=\"password\"></form>",
  "",
].join("\n");

describe("reviewed anonymized Regression Vault", () => {
  it("removes routing/contact/destination identifiers deterministically", () => {
    const sanitized = sanitizeRegressionSample(PRIVATE_SAMPLE);
    expect(sanitized).toContain("sender@sample.invalid");
    expect(sanitized).toContain("https://unsafe.example/");
    expect(sanitized).toContain("[redacted-phone]");
    for (const privateValue of ["private.person", "real-company.test", "customer@home.test", "203.0.113.77", "555-1234", "private-login.test"]) {
      expect(sanitized).not.toContain(privateValue);
    }
    expect(sanitizeRegressionSample(PRIVATE_SAMPLE)).toBe(sanitized);
  });

  it("requires attestation, exact review digest, cross-provider proof and deduplicated approval", async () => {
    const root = temporaryRoot();
    const candidateRoot = join(root, "candidates");
    const vaultRoot = join(root, "vault");
    expect(() => intakeRegressionSample({
      candidateRoot, rawEml: PRIVATE_SAMPLE, category: "credential_phishing", kind: "malicious",
      expectedVerdict: "non_safe", authenticationTrust: "unknown", attestedNoPrivateContent: false,
    })).toThrow(/attest/);
    const candidate = intakeRegressionSample({
      candidateRoot, rawEml: PRIVATE_SAMPLE, category: "credential_phishing", kind: "malicious",
      expectedVerdict: "non_safe", authenticationTrust: "unknown", attestedNoPrivateContent: true,
    });
    await expect(approveRegressionCandidate({
      candidateRoot, candidateId: candidate.candidateId, reviewDigest: "0".repeat(64), reviewerRole: "security_reviewer", vaultRoot,
    })).rejects.toThrow(/Review digest/);
    const approved = await approveRegressionCandidate({
      candidateRoot, candidateId: candidate.candidateId, reviewDigest: candidate.sanitizedSha256, reviewerRole: "security_reviewer", vaultRoot,
    });
    expect(Object.values(approved.outcomes).every((verdict) => verdict !== "safe")).toBe(true);
    await expect(approveRegressionCandidate({
      candidateRoot, candidateId: candidate.candidateId, reviewDigest: candidate.sanitizedSha256, reviewerRole: "security_reviewer", vaultRoot,
    })).rejects.toThrow(/already contains/);
    await expect(verifyRegressionVault(vaultRoot)).resolves.toHaveLength(1);

    const samplePath = join(vaultRoot, approved.entry.file);
    writeFileSync(samplePath, `${readFileSync(samplePath, "utf8")}tampered\n`, "utf8");
    await expect(verifyRegressionVault(vaultRoot)).rejects.toThrow(/SHA-256/);
  });

  it("rejects schema drift, duplicate digests and unsorted entries", () => {
    expect(() => assertRegressionVaultManifest({ schemaVersion: 1, entries: [], extra: true })).toThrow(/schema/);
    const entry = {
      id: "a".repeat(32), category: "credential_phishing", kind: "malicious", expectedVerdict: "non_safe",
      authenticationTrust: "unknown", file: `samples/credential_phishing/${"a".repeat(32)}.eml`, sha256: "b".repeat(64),
      provenance: { source: "verified_anonymized_operator_sample", sanitizerVersion: 1, reviewDigest: "b".repeat(64), reviewerRole: "security_reviewer" },
    };
    expect(() => assertRegressionVaultManifest({ schemaVersion: 1, entries: [entry, { ...entry, id: "c".repeat(32), file: `samples/credential_phishing/${"c".repeat(32)}.eml` }] })).toThrow(/duplicate/);
  });
});
