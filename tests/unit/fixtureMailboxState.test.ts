import { describe, expect, it } from "vitest";
import { createAdapter, type AdapterConfig } from "../../server/src/api/adapterConfig.js";
import { secureAdapterConfigInMemory } from "../../server/src/security/secureAdapterConfig.js";
import type { Provider } from "../../server/src/canonical/envelope.js";

const providers: Provider[] = ["gmail", "icloud", "outlook", "yahoo", "imap"];

async function folderMessageIds(config: AdapterConfig, normalized: "inbox" | "spam" | "trash") {
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
      const secured = secureAdapterConfigInMemory(config).config;
      expect(secured.mode).toBe("fixture");
      if (secured.mode !== "fixture") throw new Error("fixture config expected");
      const runtimeConfig: AdapterConfig = {
        provider,
        mode: "fixture",
        fixtureFolderOverrides: secured.fixtureFolderOverrides,
        fixtureFolderState: secured.fixtureFolderState,
      };
      const initialInbox = await folderMessageIds(runtimeConfig, "inbox");
      const initialSpam = await folderMessageIds(runtimeConfig, "spam");

      expect(initialInbox.length).toBeGreaterThan(0);
      expect(initialSpam.length).toBeGreaterThan(0);
      expect(secured.fixtureFolderState).toBeInstanceOf(SharedArrayBuffer);

      const movedId = initialInbox[0]!;
      const actionAdapter = createAdapter(runtimeConfig);
      const controller = new AbortController();
      try {
        await actionAdapter.connect(controller.signal);
        const result = await actionAdapter.reportSpam([movedId], controller.signal);
        expect(result).toEqual({ requested: 1, reported: 1, mode: "fixture_junk_move" });
      } finally {
        await actionAdapter.disconnect();
      }

      const rescannedInbox = await folderMessageIds(runtimeConfig, "inbox");
      const rescannedSpam = await folderMessageIds(runtimeConfig, "spam");
      expect(rescannedInbox).not.toContain(movedId);
      expect(rescannedSpam).toContain(movedId);
    });

    it(`${provider} preserves a Worker-structured-clone Trash move in the owning fixture session`, async () => {
      const secured = secureAdapterConfigInMemory({ provider, mode: "fixture" }).config;
      expect(secured.mode).toBe("fixture");
      if (secured.mode !== "fixture") throw new Error("fixture config expected");
      expect(secured.fixtureFolderState).toBeInstanceOf(SharedArrayBuffer);

      const ownerConfig: AdapterConfig = {
        provider,
        mode: "fixture",
        fixtureFolderOverrides: secured.fixtureFolderOverrides,
        fixtureFolderState: secured.fixtureFolderState,
      };
      const workerClone = structuredClone(ownerConfig);
      expect(workerClone.fixtureFolderState).toBeInstanceOf(SharedArrayBuffer);

      const initialInbox = await folderMessageIds(ownerConfig, "inbox");
      const movedId = initialInbox[0]!;
      const workerAdapter = createAdapter(workerClone);
      const controller = new AbortController();
      try {
        await workerAdapter.connect(controller.signal);
        await workerAdapter.moveToTrash([movedId], controller.signal);
      } finally {
        await workerAdapter.disconnect();
      }

      const ownerInbox = await folderMessageIds(ownerConfig, "inbox");
      const ownerTrash = await folderMessageIds(ownerConfig, "trash");
      expect(ownerInbox).not.toContain(movedId);
      expect(ownerTrash).toContain(movedId);
    });
  }
});
