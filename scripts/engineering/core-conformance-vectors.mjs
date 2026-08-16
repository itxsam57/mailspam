import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { FixtureAdapter } from "../../server/dist/adapters/fixtures/fixtureAdapter.js";
import { annotateRelationshipHistory } from "../../server/dist/engine/relationshipHistory.js";
import { evaluatePortableCore } from "../../server/dist/core/portableCore.js";

const root = process.cwd();
const outputPath = resolve(root, "fixtures/core-conformance/v1/vectors.json");
const diagnosticOutputPath = resolve(root, "artifacts/engineering/generated-core-vectors.json");
const corpusRoot = resolve(root, "fixtures/scam-corpus");
const providers = ["gmail", "icloud", "outlook", "yahoo", "imap"];
const fixedFetchedAt = "2026-08-11T00:00:00.000Z";

const emptyPolicy = () => ({
  blockedSenders: [],
  blockedDomains: [],
  trustedSenders: [],
  approvedExceptions: [],
  unsubscribedActions: [],
  reportedCampaigns: [],
});

async function canonicalEnvelope(provider, fixture, id) {
  const rawEml = readFileSync(resolve(corpusRoot, fixture), "utf8");
  const adapter = new FixtureAdapter(provider, [{
    id,
    rawEml,
    folder: "inbox",
    providerFolderName: "INBOX",
    authenticationTrust: "trusted",
  }]);
  const signal = new AbortController().signal;
  await adapter.connect(signal);
  try {
    const inbox = (await adapter.listFolders(signal)).find((folder) => folder.normalized === "inbox");
    if (!inbox) throw new Error("Conformance fixture Inbox is missing.");
    const page = await adapter.fetchPage(inbox, null, 1, signal);
    const envelope = page.envelopes[0];
    if (!envelope) throw new Error("Conformance fixture did not normalize an envelope.");
    annotateRelationshipHistory(envelope, undefined);
    envelope.diagnostics.fetchedAt = fixedFetchedAt;
    return envelope;
  } finally {
    await adapter.disconnect();
  }
}

async function vector(id, provider, fixture, modify = () => {}) {
  const request = {
    schemaVersion: 1,
    envelope: await canonicalEnvelope(provider, fixture, `${id}-message`),
    personalPolicy: emptyPolicy(),
    intelligence: { state: "verified", entries: [] },
  };
  modify(request);
  return { id, request, expectedResponse: evaluatePortableCore(request) };
}

export async function buildCoreConformanceBundle() {
  const vectors = [];
  for (const provider of providers) {
    vectors.push(await vector(
      `provider-${provider}-credential-phishing`,
      provider,
      "credential_phishing/malicious-plain.eml",
    ));
  }
  vectors.push(await vector(
    "adversarial-verified-feed-unavailable",
    "gmail",
    "brand_impersonation/legit-plain.eml",
    (request) => { request.intelligence = { state: "unavailable", entries: null }; },
  ));
  vectors.push(await vector(
    "adversarial-personal-block-precedence",
    "outlook",
    "brand_impersonation/legit-plain.eml",
    (request) => { request.personalPolicy.blockedDomains = [request.envelope.from.domain]; },
  ));
  return {
    formatVersion: 1,
    portableCoreSchemaVersion: 1,
    generatedBy: "scripts/engineering/core-conformance-vectors.mjs",
    vectors,
  };
}

const serialized = `${JSON.stringify(await buildCoreConformanceBundle(), null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (!existsSync(outputPath) || readFileSync(outputPath, "utf8") !== serialized) {
    mkdirSync(dirname(diagnosticOutputPath), { recursive: true });
    writeFileSync(diagnosticOutputPath, serialized, "utf8");
    console.error(`Portable core conformance vectors are missing or stale. Generated candidate written to ${diagnosticOutputPath}. Run npm run generate:core-vectors and commit the result.`);
    process.exit(1);
  }
  console.log("Portable core conformance vectors match the compiled engine for all five providers and adversarial cases.");
} else {
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, serialized, "utf8");
  console.log(`Portable core conformance vectors written: ${outputPath}`);
}
