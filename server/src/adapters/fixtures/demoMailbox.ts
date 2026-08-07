import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { FixtureAdapter, type FixtureMessage } from "./fixtureAdapter.js";
import type { Provider } from "../../canonical/envelope.js";
import type { FixtureFolderOverrides } from "../../api/adapterConfig.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CORPUS_DIR = join(__dirname, "../../../../fixtures/scam-corpus");

interface ManifestEntry { category: string; kind: "malicious" | "legit"; file: string; variant: string }

/**
 * Builds a demo mailbox from the synthetic scam corpus: malicious "plain"
 * variants land in Inbox (as if they slipped past provider spam filtering,
 * which is the realistic case this app targets) and Spam; legit controls
 * land in Inbox. Fixture folder mutations are held in the account session so
 * a provider-confirmed move remains visible on the next scan.
 */
export function buildDemoMailbox(
  provider: Provider,
  folderOverrides: FixtureFolderOverrides = {},
): FixtureAdapter {
  const manifest: ManifestEntry[] = JSON.parse(readFileSync(join(CORPUS_DIR, "manifest.json"), "utf-8"));
  const plainOnly = manifest.filter((m) => m.variant === "plain");
  let maliciousIndex = 0;

  const messages: FixtureMessage[] = plainOnly.map((entry, i) => {
    const rawEml = readFileSync(join(CORPUS_DIR, entry.file), "utf-8");
    const id = `${entry.category}-${entry.kind}-${i}`;

    if (entry.kind === "malicious") {
      const defaultFolder = maliciousIndex++ % 2 === 0 ? ("inbox" as const) : ("spam" as const);
      const folder = folderOverrides[id] ?? defaultFolder;
      return {
        id,
        rawEml,
        folder,
        providerFolderName: folder === "inbox" ? "INBOX" : folder === "spam" ? "Spam" : "Trash",
      };
    }

    const folder = folderOverrides[id] ?? ("inbox" as const);
    return {
      id,
      rawEml,
      folder,
      providerFolderName: folder === "inbox" ? "INBOX" : folder === "spam" ? "Spam" : "Trash",
    };
  });

  return new FixtureAdapter(provider, messages, folderOverrides);
}
