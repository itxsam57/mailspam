import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EncryptedFileInboundEventStateRepository } from "../../server/src/realtime/inboundEventPersistence.js";

const roots: string[] = [];
function root(): string {
  const value = mkdtempSync(join(tmpdir(), "email-shield-inbound-events-"));
  roots.push(value);
  return value;
}

afterEach(() => {
  while (roots.length) rmSync(roots.pop()!, { recursive: true, force: true });
});

describe("encrypted inbound event replay state", () => {
  it("round-trips replay hashes and checkpoints without storing them in plaintext", () => {
    const directory = root();
    const repository = new EncryptedFileInboundEventStateRepository(directory, randomBytes(32));
    const replayKey = "a".repeat(64);
    const checkpointKey = "b".repeat(64);
    repository.save({
      schemaVersion: 1,
      rememberedEventKeys: [replayKey],
      checkpoints: { [checkpointKey]: "provider-history-12345" },
    });

    expect(repository.load()).toEqual({
      schemaVersion: 1,
      rememberedEventKeys: [replayKey],
      checkpoints: { [checkpointKey]: "provider-history-12345" },
    });
    const raw = readFileSync(join(directory, "inbound-event-state.enc.json"), "utf8");
    expect(raw).not.toContain(replayKey);
    expect(raw).not.toContain("provider-history-12345");
  });

  it("fails closed when encrypted state is modified", () => {
    const directory = root();
    const repository = new EncryptedFileInboundEventStateRepository(directory, randomBytes(32));
    repository.save({ schemaVersion: 1, rememberedEventKeys: ["c".repeat(64)], checkpoints: {} });
    const path = join(directory, "inbound-event-state.enc.json");
    const envelope = JSON.parse(readFileSync(path, "utf8")) as { ciphertext: string } & Record<string, unknown>;
    const ciphertext = Buffer.from(envelope.ciphertext, "base64");
    ciphertext[0] = ciphertext[0]! ^ 0x01;
    envelope.ciphertext = ciphertext.toString("base64");
    writeFileSync(path, JSON.stringify(envelope));

    expect(() => repository.load()).toThrow(/could not be read/i);
  });

  it("does not accept another installation's encryption key", () => {
    const directory = root();
    new EncryptedFileInboundEventStateRepository(directory, randomBytes(32)).save({
      schemaVersion: 1,
      rememberedEventKeys: ["d".repeat(64)],
      checkpoints: {},
    });
    expect(() => new EncryptedFileInboundEventStateRepository(directory, randomBytes(32)).load())
      .toThrow(/could not be read/i);
  });

  it("validates replay-state schema before writing", () => {
    const repository = new EncryptedFileInboundEventStateRepository(root(), randomBytes(32));
    expect(() => repository.save({
      schemaVersion: 1,
      rememberedEventKeys: ["raw-provider-id"],
      checkpoints: {},
    })).toThrow(/replay state is invalid/i);
  });
});
