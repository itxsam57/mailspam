import type {
  EmailAdapter,
  FetchPage,
  FolderDescriptor,
  SpamReportResult,
} from "../../canonical/adapter.js";
import type { Provider, NormalizedFolder } from "../../canonical/envelope.js";
import { normalizeRawMessage } from "../../util/mimeNormalize.js";

export interface FixtureMessage {
  id: string;
  rawEml: string;
  folder: NormalizedFolder;
  providerFolderName: string;
}

/**
 * One adapter implementation shared by every provider's fixture — this is
 * the direct proof of spec Section 4's rule: "No adapter may have its own
 * weaker security logic. All adapters must normalize messages into one
 * canonical envelope and use the same detection pipeline." The only thing
 * that differs per provider is the `provider` tag and which folder
 * layout/quirks are simulated; the actual MIME normalization and every
 * downstream detection layer are identical.
 */
export class FixtureAdapter implements EmailAdapter {
  readonly provider: Provider;
  private messages: FixtureMessage[];
  private connected = false;

  constructor(provider: Provider, messages: FixtureMessage[]) {
    this.provider = provider;
    this.messages = messages.map((message) => ({ ...message }));
  }

  async connect(signal: AbortSignal): Promise<void> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    this.connected = true;
  }

  async listFolders(signal: AbortSignal): Promise<FolderDescriptor[]> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const seen = new Map<string, FolderDescriptor>();
    for (const m of this.messages) {
      if (!seen.has(m.providerFolderName)) {
        seen.set(m.providerFolderName, {
          providerFolderName: m.providerFolderName,
          normalized: m.folder,
          includedByDefault: !["sent", "drafts", "trash"].includes(m.folder),
        });
      }
    }
    return [...seen.values()];
  }

  async fetchPage(
    folder: FolderDescriptor,
    cursor: string | null,
    pageSize: number,
    signal: AbortSignal
  ): Promise<FetchPage> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const inFolder = this.messages.filter((m) => m.providerFolderName === folder.providerFolderName);
    const start = cursor ? Number(cursor) : 0;
    const slice = inFolder.slice(start, start + pageSize);

    const envelopes = [];
    for (const m of slice) {
      if (signal.aborted) throw new DOMException("Aborted", "AbortError");
      envelopes.push(
        await normalizeRawMessage(m.rawEml, {
          provider: this.provider,
          accountProof: `fixture-account-proof-${this.provider}`,
          providerFolderName: folder.providerFolderName,
          normalizedFolder: folder.normalized,
          providerNativeId: m.id,
        })
      );
    }

    const nextIndex = start + slice.length;
    return { envelopes, nextCursor: nextIndex < inFolder.length ? String(nextIndex) : null, done: nextIndex >= inFolder.length };
  }

  private moveFixtureMessages(messageIds: string[], target: NormalizedFolder): number {
    const targetMessage = this.messages.find((message) => message.folder === target);
    if (!targetMessage) throw new Error(`Fixture mailbox does not contain a ${target} folder.`);
    const idSet = new Set(messageIds);
    let moved = 0;
    for (const message of this.messages) {
      if (!idSet.has(message.id)) continue;
      message.folder = target;
      message.providerFolderName = targetMessage.providerFolderName;
      moved++;
    }
    if (moved !== idSet.size) {
      throw new Error(`Fixture mailbox found ${moved} of ${idSet.size} requested message(s).`);
    }
    return moved;
  }

  async moveToTrash(messageIds: string[], signal: AbortSignal): Promise<void> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    this.moveFixtureMessages(messageIds, "trash");
  }

  async reportSpam(messageIds: string[], signal: AbortSignal): Promise<SpamReportResult> {
    if (signal.aborted) throw new DOMException("Aborted", "AbortError");
    const reported = this.moveFixtureMessages(messageIds, "spam");
    return { requested: messageIds.length, reported, mode: "fixture_junk_move" };
  }

  async disconnect(): Promise<void> {
    this.connected = false;
  }
}
