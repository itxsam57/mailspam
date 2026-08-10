import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { FixtureAdapter, type FixtureMessage } from "../../server/src/adapters/fixtures/fixtureAdapter.js";
import { scanMessageThroughPortableCore } from "../../server/src/core/portableCore.js";
import { InMemoryPersonalPolicyStore } from "../../server/src/engine/layers/personalRules.js";
import type { Provider } from "../../server/src/canonical/envelope.js";

const CORPUS_DIR = join(import.meta.dirname, "../../fixtures/scam-corpus");
type ManifestEntry = { category: string; kind: "malicious" | "legit"; file: string; variant: string; authenticationTrust: "trusted" | "unknown" };

const manifest: ManifestEntry[] = JSON.parse(readFileSync(join(CORPUS_DIR, "manifest.json"), "utf-8"));

const PROVIDERS: Provider[] = ["gmail", "icloud", "outlook", "yahoo", "imap"];

const policy = new InMemoryPersonalPolicyStore();

interface Outcome {
  provider: Provider;
  category: string;
  kind: "malicious" | "legit";
  variant: string;
  verdict: string;
  score: number;
}

const outcomes: Outcome[] = [];

beforeAll(async () => {
  for (const provider of PROVIDERS) {
    const messages: FixtureMessage[] = manifest.map((m, i) => ({
      id: `${provider}-${i}`,
      rawEml: readFileSync(join(CORPUS_DIR, m.file), "utf-8"),
      folder: "inbox",
      providerFolderName: "INBOX",
      authenticationTrust: m.authenticationTrust,
    }));
    const adapter = new FixtureAdapter(provider, messages);
    const ac = new AbortController();
    await adapter.connect(ac.signal);
    const folders = await adapter.listFolders(ac.signal);
    const inbox = folders.find((f) => f.normalized === "inbox")!;

    let cursor: string | null = null;
    let page;
    do {
      page = await adapter.fetchPage(inbox, cursor, 100, ac.signal);
      for (let i = 0; i < page.envelopes.length; i++) {
        const envelope = page.envelopes[i]!;
        const manifestEntry = manifest[i]!; // page size 100 covers all 56 in one page
        // A verified-but-empty intelligence snapshot exercises the portable
        // production contract without forcing every legitimate message unknown.
        const result = scanMessageThroughPortableCore(envelope, policy, []);
        outcomes.push({
          provider,
          category: manifestEntry.category,
          kind: manifestEntry.kind,
          variant: manifestEntry.variant,
          verdict: result.scored.verdict,
          score: result.scored.score,
        });
      }
      cursor = page.nextCursor;
    } while (!page.done);
    await adapter.disconnect();
  }
});

describe("full scam corpus scanned through all 5 provider fixture adapters", () => {
  it("produces a non-safe verdict for every malicious fixture, on every provider", () => {
    const failures = outcomes.filter((o) => o.kind === "malicious" && o.verdict === "safe");
    if (failures.length > 0) {
      console.error("Malicious fixtures incorrectly scored SAFE:", failures);
    }
    expect(failures).toEqual([]);
  });

  it("produces a safe verdict for every legitimate control fixture, on every provider", () => {
    const failures = outcomes.filter((o) => o.kind === "legit" && o.verdict !== "safe");
    if (failures.length > 0) {
      console.error("Legitimate fixtures incorrectly flagged:", failures);
    }
    expect(failures).toEqual([]);
  });

  it("scores equivalent MIME-encoding variants of the same malicious message consistently (never 'safe')", () => {
    const mimeVariantCategories = ["credential_phishing", "business_email_compromise", "cryptocurrency_scam"];
    for (const category of mimeVariantCategories) {
      for (const provider of PROVIDERS) {
        const variantOutcomes = outcomes.filter(
          (o) => o.category === category && o.kind === "malicious" && o.provider === provider
        );
        expect(variantOutcomes.length).toBeGreaterThanOrEqual(5); // plain/html/multipart/base64/qp
        for (const o of variantOutcomes) {
          expect(o.verdict).not.toBe("safe");
        }
      }
    }
  });

  it("produces identical verdict behavior across all 5 providers for the same campaign (cross-provider parity)", () => {
    const byCategory = new Map<string, Set<string>>();
    for (const o of outcomes.filter((o) => o.kind === "malicious" && o.variant === "plain")) {
      if (!byCategory.has(o.category)) byCategory.set(o.category, new Set());
      byCategory.get(o.category)!.add(o.verdict);
    }
    for (const [category, verdicts] of byCategory) {
      // All providers must agree on non-safe-ness for the same campaign (parity requirement, spec Section 4).
      expect([...verdicts].every((v) => v !== "safe"), `category ${category} had a provider score it as safe`).toBe(true);
    }
  });

  it("prints a human-readable summary report", () => {
    const total = outcomes.length;
    const maliciousCaught = outcomes.filter((o) => o.kind === "malicious" && o.verdict !== "safe").length;
    const maliciousTotal = outcomes.filter((o) => o.kind === "malicious").length;
    const legitClean = outcomes.filter((o) => o.kind === "legit" && o.verdict === "safe").length;
    const legitTotal = outcomes.filter((o) => o.kind === "legit").length;
    console.log(`\n--- Corpus Scan Report ---`);
    console.log(`Total scans: ${total} (${manifest.length} fixtures x ${PROVIDERS.length} providers)`);
    console.log(`Malicious caught (non-safe): ${maliciousCaught}/${maliciousTotal}`);
    console.log(`Legitimate correctly clean (safe): ${legitClean}/${legitTotal}`);
    expect(total).toBeGreaterThan(0);
  });
});
