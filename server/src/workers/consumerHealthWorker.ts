import { parentPort, workerData } from "node:worker_threads";
import { createAdapter, type AdapterConfig } from "../api/adapterConfig.js";
import type { SecureAdapterConfig } from "../security/secureAdapterConfig.js";
import type { CanonicalEnvelope, Provider } from "../canonical/envelope.js";
import { analyzeInboxHealth } from "../consumer/inboxHealth.js";
import { analyzeMailboxHealth } from "../consumer/mailboxHealth.js";
import { discoverDigitalAccountFootprint } from "../consumer/digitalFootprint.js";

interface CleanupCriteria {
  senderAddress?: string;
  senderDomain?: string;
  olderThanDays?: number;
  keepNewest?: boolean;
}

interface HealthWorkerData {
  config: AdapterConfig | SecureAdapterConfig;
  provider: Provider;
  mode: "inspect" | "cleanup";
  cleanup?: CleanupCriteria;
}

const data = workerData as HealthWorkerData;
const controller = new AbortController();
parentPort?.on("message", (message) => { if (message?.type === "cancel") controller.abort(); });

const MAX_MESSAGES = 200;
const LIVE_IMAP_MAX_MESSAGES = 60;
const DEFAULT_PAGE = 25;
const LIVE_IMAP_PAGE = 5;

function normalizedAddress(value: string | undefined): string | null {
  if (!value) return null;
  const address = value.trim().toLowerCase();
  if (address.length < 3 || address.length > 320 || !address.includes("@")) throw new Error("Cleanup sender address is invalid.");
  return address;
}

function normalizedDomain(value: string | undefined): string | null {
  if (!value) return null;
  const domain = value.trim().toLowerCase().replace(/^@/, "");
  if (domain.length < 1 || domain.length > 253 || !/^[a-z0-9.-]+$/.test(domain)) throw new Error("Cleanup sender domain is invalid.");
  return domain;
}

function matchesCleanup(envelope: CanonicalEnvelope, criteria: CleanupCriteria, now: number): boolean {
  const address = normalizedAddress(criteria.senderAddress);
  const domain = normalizedDomain(criteria.senderDomain);
  if (!address && !domain) throw new Error("Bulk cleanup requires an exact sender address or domain selected from Inbox Health.");
  if (address && envelope.from.address?.toLowerCase() !== address) return false;
  if (domain && envelope.from.domain?.toLowerCase() !== domain) return false;
  if (criteria.olderThanDays !== undefined) {
    if (!Number.isSafeInteger(criteria.olderThanDays) || criteria.olderThanDays < 1 || criteria.olderThanDays > 3650) {
      throw new Error("Cleanup age must be 1-3650 whole days.");
    }
    const timestamp = Date.parse(envelope.date);
    if (!Number.isFinite(timestamp) || timestamp > now - criteria.olderThanDays * 24 * 60 * 60 * 1_000) return false;
  }
  return envelope.folder === "inbox" || envelope.folder === "archive";
}

async function collectMailbox(adapter: ReturnType<typeof createAdapter>): Promise<{ envelopes: CanonicalEnvelope[]; incomplete: boolean; reasons: string[] }> {
  await adapter.connect(controller.signal);
  const folders = await adapter.listFolders(controller.signal);
  const targets = folders.filter((folder) => ["inbox", "spam", "sent", "archive"].includes(folder.normalized));
  if (!targets.some((folder) => folder.normalized === "inbox")) throw new Error("Inbox folder was not found for health inspection.");
  const liveImap = data.config.mode === "live" && ["icloud", "yahoo", "imap"].includes(data.provider);
  const maxMessages = liveImap ? LIVE_IMAP_MAX_MESSAGES : MAX_MESSAGES;
  const pageSize = liveImap ? LIVE_IMAP_PAGE : DEFAULT_PAGE;
  const envelopes: CanonicalEnvelope[] = [];
  const reasons: string[] = [];

  for (const folder of targets) {
    let cursor: string | null = null;
    let done = false;
    while (!done && envelopes.length < maxMessages) {
      if (controller.signal.aborted) throw new DOMException("Aborted", "AbortError");
      const requestSize = Math.min(pageSize, maxMessages - envelopes.length);
      const previous = cursor;
      const page = await adapter.fetchPage(folder, cursor, requestSize, controller.signal);
      envelopes.push(...page.envelopes.slice(0, requestSize));
      done = page.done || !page.nextCursor || envelopes.length >= maxMessages;
      cursor = done ? null : page.nextCursor;
      if (!done && page.envelopes.length === 0 && page.nextCursor === previous) throw new Error("Provider health inspection cursor did not advance.");
    }
    if (envelopes.length >= maxMessages) break;
  }

  const incomplete = envelopes.length >= maxMessages;
  if (incomplete) reasons.push(`Mailbox health inspection reached its bounded ${maxMessages}-message limit.`);
  return { envelopes, incomplete, reasons };
}

async function inspect(adapter: ReturnType<typeof createAdapter>) {
  const collected = await collectMailbox(adapter);
  const inboxHealth = analyzeInboxHealth(collected.envelopes, {
    sourceIncomplete: collected.incomplete,
    sourceIncompleteReasons: collected.reasons,
  });
  const mailboxHealth = await analyzeMailboxHealth({
    provider: data.provider,
    envelopes: collected.envelopes,
    signal: controller.signal,
  });
  const digitalFootprint = discoverDigitalAccountFootprint(collected.envelopes);
  return { inboxHealth, mailboxHealth, digitalFootprint };
}

async function cleanup(adapter: ReturnType<typeof createAdapter>) {
  if (!data.cleanup) throw new Error("Bulk cleanup criteria are required.");
  const collected = await collectMailbox(adapter);
  const now = Date.now();
  const matches = collected.envelopes
    .filter((envelope) => matchesCleanup(envelope, data.cleanup!, now))
    .sort((left, right) => Date.parse(right.date) - Date.parse(left.date));
  const selected = data.cleanup.keepNewest === true ? matches.slice(1) : matches;
  const ids = [...new Set(selected.map((envelope) => envelope.providerNativeId).filter(Boolean))].slice(0, 100);
  if (ids.length) await adapter.moveToTrash(ids, controller.signal);
  return {
    matched: matches.length,
    movedToTrash: ids.length,
    keptNewest: data.cleanup.keepNewest === true && matches.length > 0,
    bounded: collected.incomplete || selected.length > ids.length,
  };
}

async function main() {
  const adapter = createAdapter(data.config);
  try {
    const result = data.mode === "cleanup" ? await cleanup(adapter) : await inspect(adapter);
    parentPort?.postMessage({ type: "result", result });
  } finally {
    await adapter.disconnect().catch(() => undefined);
  }
}

void main()
  .catch((error) => parentPort?.postMessage({ type: "error", error: error instanceof Error ? error.message : String(error) }))
  .finally(() => parentPort?.close());
