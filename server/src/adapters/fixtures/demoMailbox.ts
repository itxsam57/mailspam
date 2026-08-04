import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { FixtureAdapter, type FixtureMessage } from "./fixtureAdapter.js";
import type { Provider } from "../../canonical/envelope.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CORPUS_DIR = join(__dirname, "../../../../fixtures/scam-corpus");

interface ManifestEntry { category: string; kind: "malicious" | "legit"; file: string; variant: string }

/**
 * Builds a demo mailbox from the synthetic scam corpus: malicious "plain"
 * variants land in Inbox (as if they slipped past provider spam filtering,
 * which is the realistic case this app targets) and Spam; legit controls
 * land in Inbox and Sent. This is exactly what "connect a fixture account"
 * exercises in the dashboard, so a user can see the full engine working
 * end-to-end before ever pointing it at a real mailbox.
 */
export function buildDemoMailbox(provider: Provider): FixtureAdapter {
  const manifest: ManifestEntry[] = JSON.parse(readFileSync(join(CORPUS_DIR, "manifest.json"), "utf-8"));
  const plainOnly = manifest.filter((m) => m.variant === "plain");

  const messages: FixtureMessage[] = plainOnly.map((entry, i) => {
    const rawEml = readFileSync(join(CORPUS_DIR, entry.file), "utf-8");
    if (entry.kind === "malicious") {
      // Split roughly half into Inbox (evaded spam filter) and half into Spam.
      const folder = i % 2 === 0 ? ("inbox" as const) : ("spam" as const);
      return { id: `${entry.category}-malicious-${i}`, rawEml, folder, providerFolderName: folder === "inbox" ? "INBOX" : "Spam" };
    }
    return { id: `${entry.category}-legit-${i}`, rawEml, folder: "inbox" as const, providerFolderName: "INBOX" };
  });

  return new FixtureAdapter(provider, messages);
}
