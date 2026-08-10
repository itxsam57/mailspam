import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { FixtureAdapter, type FixtureMessage } from "../adapters/fixtures/fixtureAdapter.js";
import { scanMessage } from "../engine/pipeline.js";
import { InMemoryPersonalPolicyStore } from "../engine/layers/personalRules.js";
import type { Provider } from "../canonical/envelope.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CORPUS_DIR = join(__dirname, "../../../fixtures/scam-corpus");
const PROVIDERS: Provider[] = ["gmail", "icloud", "outlook", "yahoo", "imap"];

interface ManifestEntry {
  category: string;
  kind: "malicious" | "legit";
  file: string;
  variant: string;
  authenticationTrust: "trusted" | "unknown";
}

export interface DevTestReport {
  generatedAt: string;
  totalScans: number;
  maliciousCaught: number;
  maliciousTotal: number;
  legitClean: number;
  legitTotal: number;
  perCategory: Array<{
    category: string;
    maliciousCaught: number;
    maliciousTotal: number;
    legitClean: number;
    legitTotal: number;
  }>;
  crossProviderParityFailures: Array<{ category: string; provider: string; verdict: string }>;
  falsePositives: Array<{ category: string; provider: string; variant: string }>;
  falseNegatives: Array<{ category: string; provider: string; variant: string }>;
}

/**
 * Spec 12: "one command produces a full report." This is that command,
 * exposed via GET /api/dev/test-suite and surfaced as a single dashboard
 * panel — runs the entire scam corpus through all 5 provider fixture
 * adapters and the real detection pipeline (same code path production
 * scans use, not a separate test-only shortcut).
 *
 * Authentication provenance is consumed from the generated corpus manifest;
 * this runner must never infer trust from provider, category, or verdict kind.
 */
export async function runDeveloperTestSuite(): Promise<DevTestReport> {
  const manifest: ManifestEntry[] = JSON.parse(readFileSync(join(CORPUS_DIR, "manifest.json"), "utf-8"));
  const policy = new InMemoryPersonalPolicyStore();
  const deps = { personalPolicy: policy, threatFeed: { getVerifiedEntries: () => [] } };

  const outcomes: Array<{ provider: Provider; category: string; kind: "malicious" | "legit"; variant: string; verdict: string }> = [];

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
    const inbox = folders[0]!;
    const page = await adapter.fetchPage(inbox, null, 200, ac.signal);
    for (let i = 0; i < page.envelopes.length; i++) {
      const result = scanMessage(page.envelopes[i]!, deps);
      const m = manifest[i]!;
      outcomes.push({ provider, category: m.category, kind: m.kind, variant: m.variant, verdict: result.scored.verdict });
    }
    await adapter.disconnect();
  }

  const categories = [...new Set(manifest.map((m) => m.category))];
  const perCategory = categories.map((category) => {
    const catOutcomes = outcomes.filter((o) => o.category === category);
    return {
      category,
      maliciousCaught: catOutcomes.filter((o) => o.kind === "malicious" && o.verdict !== "safe").length,
      maliciousTotal: catOutcomes.filter((o) => o.kind === "malicious").length,
      legitClean: catOutcomes.filter((o) => o.kind === "legit" && o.verdict === "safe").length,
      legitTotal: catOutcomes.filter((o) => o.kind === "legit").length,
    };
  });

  const crossProviderParityFailures = outcomes
    .filter((o) => o.kind === "malicious" && o.variant === "plain" && o.verdict === "safe")
    .map((o) => ({ category: o.category, provider: o.provider, verdict: o.verdict }));

  const falsePositives = outcomes
    .filter((o) => o.kind === "legit" && o.verdict !== "safe")
    .map((o) => ({ category: o.category, provider: o.provider, variant: o.variant }));

  const falseNegatives = outcomes
    .filter((o) => o.kind === "malicious" && o.verdict === "safe")
    .map((o) => ({ category: o.category, provider: o.provider, variant: o.variant }));

  return {
    generatedAt: new Date().toISOString(),
    totalScans: outcomes.length,
    maliciousCaught: outcomes.filter((o) => o.kind === "malicious" && o.verdict !== "safe").length,
    maliciousTotal: outcomes.filter((o) => o.kind === "malicious").length,
    legitClean: outcomes.filter((o) => o.kind === "legit" && o.verdict === "safe").length,
    legitTotal: outcomes.filter((o) => o.kind === "legit").length,
    perCategory,
    crossProviderParityFailures,
    falsePositives,
    falseNegatives,
  };
}
