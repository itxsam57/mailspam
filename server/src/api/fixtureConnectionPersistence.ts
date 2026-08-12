import { chmodSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Provider } from "../canonical/envelope.js";
import type { AccountSession, SessionStore } from "./sessionStore.js";

const PROVIDERS = new Set<Provider>(["gmail", "outlook", "icloud", "yahoo", "imap"]);

export interface FixtureConnectionPersistence {
  remember(provider: Provider): void;
  synchronize(sessions: readonly AccountSession[]): void;
}

export const noFixtureConnectionPersistence: FixtureConnectionPersistence = {
  remember: () => undefined,
  synchronize: () => undefined,
};

/**
 * Restores synthetic provider choices after a desktop restart. This file is
 * intentionally incapable of containing messages, mailbox identities,
 * credentials, labels, provider IDs, or user-entered configuration.
 */
export class FileFixtureConnectionPersistence implements FixtureConnectionPersistence {
  readonly filePath: string;
  private providers = new Set<Provider>();

  constructor(dataDirectory: string) {
    this.filePath = join(dataDirectory, "fixture-connections.json");
    try {
      const parsed = JSON.parse(readFileSync(this.filePath, "utf8")) as unknown;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("invalid root");
      const record = parsed as Record<string, unknown>;
      if (record.version !== 1 || !Array.isArray(record.providers) || Object.keys(record).some((key) => !["version", "providers"].includes(key))) {
        throw new Error("invalid schema");
      }
      for (const value of record.providers) {
        if (typeof value !== "string" || !PROVIDERS.has(value as Provider)) throw new Error("invalid provider");
        this.providers.add(value as Provider);
      }
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "ENOENT") throw new Error("Fixture connection state is malformed; remove fixture-connections.json and reconnect synthetic providers.");
    }
  }

  restore(store: SessionStore): void {
    for (const provider of this.providers) {
      store.create(provider, `${provider} (fixture)`, { provider, mode: "fixture" });
    }
  }

  remember(provider: Provider): void {
    this.providers.add(provider);
    this.save();
  }

  synchronize(sessions: readonly AccountSession[]): void {
    this.providers = new Set(sessions
      .filter((session) => session.config.mode === "fixture")
      .map((session) => session.provider)
      .filter((provider): provider is Provider => PROVIDERS.has(provider as Provider)));
    this.save();
  }

  private save(): void {
    const temporaryPath = `${this.filePath}.${process.pid}.tmp`;
    const body = `${JSON.stringify({ version: 1, providers: [...this.providers].sort() }, null, 2)}\n`;
    writeFileSync(temporaryPath, body, { encoding: "utf8", mode: 0o600, flag: "w" });
    try { chmodSync(temporaryPath, 0o600); } catch {}
    renameSync(temporaryPath, this.filePath);
  }
}
