import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { providerCapabilitySnapshot } from "../../server/dist/adapters/providerCapabilities.js";
import { FixtureAdapter } from "../../server/dist/adapters/fixtures/fixtureAdapter.js";

const root = process.cwd();
const expected = JSON.parse(readFileSync(resolve(root, "fixtures/provider-compatibility/v1/capabilities.json"), "utf8"));
const actual = { schemaVersion: 1, providers: providerCapabilitySnapshot() };
if (`${JSON.stringify(actual, null, 2)}\n` !== `${JSON.stringify(expected, null, 2)}\n`) {
  throw new Error("Provider capability contract changed. Review it and update the versioned snapshot deliberately.");
}

for (const contract of actual.providers) {
  if (!Object.values(contract.capabilities).every((supported) => supported === true)) {
    throw new Error(`${contract.provider} does not satisfy the required release capability set.`);
  }
  const mailboxState = {};
  const adapter = new FixtureAdapter(contract.provider, [{
    id: "compatibility-sample",
    rawEml: "From: Sender <sender@sample.invalid>\nTo: Review <review@sample.invalid>\nSubject: Compatibility\nMessage-ID: <compatibility@sample.invalid>\nContent-Type: text/plain; charset=utf-8\n\nOrdinary fixture message.\n",
    folder: "inbox",
    providerFolderName: "INBOX",
    authenticationTrust: "unknown",
  }], mailboxState);
  const controller = new AbortController();
  await adapter.connect(controller.signal);
  const folders = await adapter.listFolders(controller.signal);
  const inbox = folders.find((folder) => folder.normalized === "inbox");
  if (!inbox) throw new Error(`${contract.provider} fixture lacks Inbox discovery.`);
  const page = await adapter.fetchPage(inbox, null, 1, controller.signal);
  if (page.envelopes.length !== 1 || page.envelopes[0].provider !== contract.provider || !page.done) {
    throw new Error(`${contract.provider} fixture failed bounded canonical fetch parity.`);
  }
  const report = await adapter.reportSpam(["compatibility-sample"], controller.signal);
  if (report.reported !== 1 || mailboxState["compatibility-sample"] !== "spam") throw new Error(`${contract.provider} fixture failed Spam/Junk parity.`);
  await adapter.moveToTrash(["compatibility-sample"], controller.signal);
  if (mailboxState["compatibility-sample"] !== "trash") throw new Error(`${contract.provider} fixture failed Trash parity.`);
  await adapter.disconnect();
  const aborted = new AbortController();
  aborted.abort();
  await adapter.connect(aborted.signal).then(
    () => { throw new Error(`${contract.provider} fixture ignored cancellation.`); },
    (error) => { if (!(error instanceof Error) || error.name !== "AbortError") throw error; },
  );
}

console.log(`Provider compatibility passed: ${actual.providers.length} versioned contracts with executable fixture parity.`);
