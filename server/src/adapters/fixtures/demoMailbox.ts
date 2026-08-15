import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  FixtureAdapter,
  type FixtureFolderOverrides,
  type FixtureMessage,
} from "./fixtureAdapter.js";
import {
  type FixtureFolderState,
  readFixtureFolderState,
  writeFixtureFolderState,
} from "./fixtureFolderState.js";
import type { Provider } from "../../canonical/envelope.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CORPUS_DIR = join(__dirname, "../../../../fixtures/scam-corpus");

interface ManifestEntry { category: string; kind: "malicious" | "legit"; file: string; variant: string; authenticationTrust: "trusted" | "unknown" }

/**
 * Builds a demo mailbox from the synthetic scam corpus: malicious "plain"
 * variants land in Inbox (as if they slipped past provider spam filtering,
 * which is the realistic case this app targets) and Spam; legit controls
 * land in Inbox. Fixture folder mutations are held in worker-shared account
 * state so a provider-confirmed move remains visible after adapter recreation
 * and across the desktop/Worker structured-clone boundary.
 *
 * The corpus is controlled test input. Its Authentication-Results values model
 * provider-produced outcomes and are therefore marked trusted explicitly here;
 * ad-hoc FixtureMessage instances remain unknown unless the test opts in.
 */
export function buildDemoMailbox(
  provider: Provider,
  folderOverrides: FixtureFolderOverrides = {},
  sharedFolderState?: FixtureFolderState,
): FixtureAdapter {
  const manifest: ManifestEntry[] = JSON.parse(readFileSync(join(CORPUS_DIR, "manifest.json"), "utf-8"));
  const plainOnly = manifest.filter((m) => m.variant === "plain");
  let maliciousIndex = 0;

  const messages: FixtureMessage[] = plainOnly.map((entry, i) => {
    const rawEml = readFileSync(join(CORPUS_DIR, entry.file), "utf-8");
    const id = `${entry.category}-${entry.kind}-${i}`;
    const defaultFolder = entry.kind === "malicious"
      ? (maliciousIndex++ % 2 === 0 ? ("inbox" as const) : ("spam" as const))
      : ("inbox" as const);
    const configuredFolder = folderOverrides[id] ?? defaultFolder;
    const sharedFolder = sharedFolderState ? readFixtureFolderState(sharedFolderState, i) : null;
    const folder = sharedFolder ?? configuredFolder;

    // Zero means this fixture slot has not been initialized yet. Seed it from
    // the same deterministic default/override used by the non-Worker adapter.
    if (sharedFolderState && sharedFolder === null) {
      writeFixtureFolderState(sharedFolderState, i, configuredFolder);
    }

    return {
      id,
      rawEml,
      folder,
      providerFolderName: folder === "inbox" ? "INBOX" : folder === "spam" ? "Spam" : "Trash",
      authenticationTrust: entry.authenticationTrust,
    };
  });

  return new FixtureAdapter(provider, messages, folderOverrides, sharedFolderState);
}
