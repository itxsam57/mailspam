import { describe, expect, it } from "vitest";
import { createAdapter, type AdapterConfig } from "../../server/src/api/adapterConfig.js";
import type { Provider } from "../../server/src/canonical/envelope.js";

const providers: Provider[] = ["gmail", "icloud", "outlook", "yahoo", "imap"];

async function folderMessageIds(config: AdapterConfig, normalized: "inbox" | "spam") {
  const adapter = createAdapter(config);
  const controller = new AbortController();
  try {
    await adapter.connect(controller.signal);
    const folders = await adapter.listFolders(controller.signal);
    const folder = folders.find((candidate) => candidate.normalized === normalized);
    expect(folder, `${config.provider} fixture should expose ${normalized}`).toBeDefined();
    const page = await adapter.fetchPage(folder!, null, 1_000, controller.signal);
    return page.envelopes.map((envelope) => envelope.providerNativeId);
  } finally {
    await adapter.disconnect();
  }
}

describe("fixture mailbox folder state", () => {
  for (const provider of providers) {
    it(`${provider} exposes Spam/Junk and preserves an exact move across adapter recreation`, async () => {
      const config: AdapterConfig = { provider, mode: "fixture" };
      const initialInbox = await folderMessageIds(config, "inbox");
      const initialSpam = await folderMessageIds(config, "spam");

      expect(initialInbox.length).toBeGreaterThan(0);
      expect(initialSpam.length).toBeGreaterThan(0);

      const movedId = initialInbox[0]!;
      const actionAdapter = createAdapter(config);
      const controller = new AbortController();
      try {
        await actionAdapter.connect(controller.signal);
        const result = await actionAdapter.reportSpam([movedId], controller.signal);
        expect(result).toEqual({ requested: 1, reported: 1, mode: "fixture_junk_move" });
      } finally {
        await actionAdapter.disconnect();
      }

      const rescannedInbox = await folderMessageIds(config, "inbox");
      const rescannedSpam = await folderMessageIds(config, "spam");
      expect(rescannedInbox).not.toContain(movedId);
      expect(rescannedSpam).toContain(movedId);
    });
  }
});
