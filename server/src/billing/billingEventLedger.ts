import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import type { BillingEventLedger } from "./billingVerification.js";
import { readBoundedUtf8File, replaceFileFromTemporaryPath } from "../util/localFileIntegrity.js";

const LEDGER_VERSION = 1 as const;
const MAX_BILLING_EVENTS = 200_000;
const MAX_LEDGER_BYTES = 64 * 1024 * 1024;
const EVENT_FINGERPRINT = /^[a-f0-9]{64}$/;
const ACCOUNT_ID = /^[a-z0-9][a-z0-9_.:-]{0,127}$/i;

interface BillingEventLedgerEntry {
  accountId: string;
  verifiedAt: number;
}

interface BillingEventLedgerDatabase {
  version: 1;
  events: Record<string, BillingEventLedgerEntry>;
}

function normalizeAccountId(value: string): string {
  const normalized = value.trim();
  if (!ACCOUNT_ID.test(normalized)) throw new Error("Billing event account ID is invalid.");
  return normalized;
}

function normalizeFingerprint(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (!EVENT_FINGERPRINT.test(normalized)) throw new Error("Billing event fingerprint is invalid.");
  return normalized;
}

function normalizeVerifiedAt(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error("Billing event verification timestamp is invalid.");
  return value;
}

function normalizeDatabase(input: unknown): BillingEventLedgerDatabase {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Billing event ledger is invalid.");
  const value = input as Record<string, unknown>;
  if (value.version !== LEDGER_VERSION || !value.events || typeof value.events !== "object" || Array.isArray(value.events)) {
    throw new Error("Billing event ledger format is unsupported.");
  }
  const rawEvents = Object.entries(value.events as Record<string, unknown>);
  if (rawEvents.length > MAX_BILLING_EVENTS) throw new Error("Billing event ledger exceeds its capacity.");
  const events: Record<string, BillingEventLedgerEntry> = {};
  for (const [fingerprint, raw] of rawEvents) {
    const key = normalizeFingerprint(fingerprint);
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("Billing event ledger entry is invalid.");
    const entry = raw as Record<string, unknown>;
    if (Object.keys(entry).some((field) => field !== "accountId" && field !== "verifiedAt")) throw new Error("Billing event ledger entry contains unsupported fields.");
    if (typeof entry.accountId !== "string" || typeof entry.verifiedAt !== "number") throw new Error("Billing event ledger entry is invalid.");
    events[key] = {
      accountId: normalizeAccountId(entry.accountId),
      verifiedAt: normalizeVerifiedAt(entry.verifiedAt),
    };
  }
  return { version: LEDGER_VERSION, events };
}

/**
 * Durable single-instance billing idempotency ledger.
 *
 * Only the SHA-256 event fingerprint, internal account ID and verification time
 * are persisted. Store receipts, webhook payloads, purchase tokens and user
 * mailbox data are never written here. At capacity the ledger fails closed
 * instead of evicting old event fingerprints and allowing a historical replay
 * to look new again.
 *
 * Multi-instance production deployments should provide the same BillingEventLedger
 * interface from a transactional shared database before horizontal scaling.
 */
export class FileBillingEventLedger implements BillingEventLedger {
  constructor(private readonly filePath: string) {}

  assertReadable(): void {
    void this.read();
  }

  has(eventFingerprint: string): boolean {
    return Object.hasOwn(this.read().events, normalizeFingerprint(eventFingerprint));
  }

  record(eventFingerprint: string, accountId: string, verifiedAt: number): void {
    const fingerprint = normalizeFingerprint(eventFingerprint);
    const normalizedAccount = normalizeAccountId(accountId);
    const timestamp = normalizeVerifiedAt(verifiedAt);
    const database = this.read();
    const existing = database.events[fingerprint];
    if (existing) {
      if (existing.accountId !== normalizedAccount) {
        throw new Error("Billing event fingerprint is already bound to a different account.");
      }
      return;
    }
    if (Object.keys(database.events).length >= MAX_BILLING_EVENTS) {
      throw new Error("Billing event ledger reached capacity; no historical idempotency entry was evicted.");
    }
    database.events[fingerprint] = { accountId: normalizedAccount, verifiedAt: timestamp };
    this.write(database);
  }

  private read(): BillingEventLedgerDatabase {
    if (!existsSync(this.filePath)) return { version: LEDGER_VERSION, events: {} };
    try {
      const raw = readBoundedUtf8File(this.filePath, {
        description: "Billing event ledger",
        maxBytes: MAX_LEDGER_BYTES,
      });
      return normalizeDatabase(JSON.parse(raw));
    } catch (error) {
      throw new Error(`Billing event ledger could not be read: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private write(database: BillingEventLedgerDatabase): void {
    const normalized = normalizeDatabase(database);
    const serialized = JSON.stringify(normalized);
    if (Buffer.byteLength(serialized, "utf8") > MAX_LEDGER_BYTES) throw new Error("Billing event ledger exceeds its file-size limit.");
    const directory = dirname(this.filePath);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    try { chmodSync(directory, 0o700); } catch {}
    const temporaryPath = `${this.filePath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
    writeFileSync(temporaryPath, serialized, { mode: 0o600 });
    replaceFileFromTemporaryPath(temporaryPath, this.filePath);
    try { chmodSync(this.filePath, 0o600); } catch {}
  }
}

export function billingEventLedgerCapacity(): number {
  return MAX_BILLING_EVENTS;
}
