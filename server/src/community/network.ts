import { homedir } from "node:os";
import { join } from "node:path";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import type { SignedFeedEntry, ThreatFeedCache } from "../engine/layers/globalIntelligence.js";
import { EncryptedCommunityAggregateStore } from "./aggregateStore.js";
import { EncryptedCommunityOutbox } from "./outbox.js";
import { CommunityReporterIdentity } from "./reporterIdentity.js";
import { CommunityFeedSigner, verifyCommunityFeed } from "./signing.js";
import type {
  CommunityReportContext,
  CommunityReportReceipt,
  CommunityReportSubmission,
  SignedCommunityFeed,
} from "./types.js";

const REMOTE_TIMEOUT_MS = 10_000;
const MAX_FLUSH_PER_REFRESH = 25;
const DEFAULT_DATA_DIRECTORY = process.env.EMAIL_SHIELD_DATA_DIR?.trim() || join(homedir(), ".email-shield");

function configuredPublicKeys(): string[] {
  const raw = process.env.EMAIL_SHIELD_COMMUNITY_PUBLIC_KEYS?.trim();
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return parsed.filter((item): item is string => typeof item === "string" && item.includes("BEGIN PUBLIC KEY"));
  } catch {}
  return raw.includes("BEGIN PUBLIC KEY") ? [raw.replace(/\\n/g, "\n")] : [];
}

function normalizeRemoteUrl(value: string | undefined | null): string | null {
  const trimmed = value?.trim();
  if (!trimmed) return null;
  const parsed = new URL(trimmed);
  const local = ["localhost", "127.0.0.1", "::1"].includes(parsed.hostname);
  if (parsed.protocol !== "https:" && !(local && parsed.protocol === "http:")) {
    throw new Error("Community service URL must use HTTPS, except localhost development.");
  }
  if (parsed.username || parsed.password) throw new Error("Community service URL must not contain credentials.");
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");
  parsed.search = "";
  parsed.hash = "";
  return parsed.toString().replace(/\/$/, "");
}

async function fetchJson(url: string, init?: RequestInit): Promise<unknown> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REMOTE_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      ...init,
      redirect: "error",
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
        ...(init?.headers ?? {}),
      },
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const message = typeof (data as { error?: unknown }).error === "string"
        ? (data as { error: string }).error
        : `Community service returned HTTP ${response.status}.`;
      throw new Error(message);
    }
    return data;
  } finally {
    clearTimeout(timeout);
  }
}

function isReceipt(value: unknown): value is CommunityReportReceipt {
  if (!value || typeof value !== "object") return false;
  const item = value as Partial<CommunityReportReceipt>;
  return item.accepted === true &&
    typeof item.duplicate === "boolean" &&
    typeof item.queued === "boolean" &&
    typeof item.campaignFingerprint === "string" &&
    typeof item.independentReporters === "number" &&
    ["candidate", "warning", "confirmed"].includes(item.status ?? "");
}

export class CommunityNetwork implements ThreatFeedCache {
  readonly dataDirectory: string;
  readonly serverEnabled: boolean;
  readonly remoteUrl: string | null;
  private readonly aggregateStore: EncryptedCommunityAggregateStore;
  private readonly reporterIdentity: CommunityReporterIdentity;
  private readonly outbox: EncryptedCommunityOutbox;
  private readonly signer: CommunityFeedSigner;
  private readonly trustedPublicKeys: string[];
  private readonly feedCachePath: string;
  private verifiedEntries: SignedFeedEntry[] | null = [];
  private cachedDocument: SignedCommunityFeed | null = null;

  constructor(options: {
    dataDirectory?: string;
    serverEnabled?: boolean;
    remoteUrl?: string | null;
    trustedPublicKeys?: string[];
  } = {}) {
    this.dataDirectory = options.dataDirectory ?? DEFAULT_DATA_DIRECTORY;
    this.serverEnabled = options.serverEnabled ?? process.env.EMAIL_SHIELD_COMMUNITY_SERVER === "1";
    this.remoteUrl = normalizeRemoteUrl(
      options.remoteUrl === undefined ? process.env.EMAIL_SHIELD_COMMUNITY_URL : options.remoteUrl,
    );
    this.aggregateStore = new EncryptedCommunityAggregateStore(this.dataDirectory);
    this.reporterIdentity = new CommunityReporterIdentity(this.dataDirectory);
    this.outbox = new EncryptedCommunityOutbox(this.dataDirectory);
    this.signer = new CommunityFeedSigner(
      this.dataDirectory,
      process.env.EMAIL_SHIELD_COMMUNITY_PRIVATE_KEY?.replace(/\\n/g, "\n"),
      process.env.EMAIL_SHIELD_COMMUNITY_PUBLIC_KEY?.replace(/\\n/g, "\n"),
    );
    this.trustedPublicKeys = options.trustedPublicKeys ?? [
      ...configuredPublicKeys(),
      ...(this.remoteUrl ? [] : [this.signer.publicPem]),
    ];
    this.feedCachePath = join(this.dataDirectory, "community-feed-cache.json");
    this.loadCachedFeed();
    if (!this.remoteUrl) this.rebuildEmbeddedFeed();
  }

  getVerifiedEntries(): SignedFeedEntry[] | null {
    return this.verifiedEntries ? structuredClone(this.verifiedEntries) : null;
  }

  reporterProof(accountKey: string): string {
    return this.reporterIdentity.proofForAccount(accountKey);
  }

  async submit(context: CommunityReportContext, accountKey: string): Promise<CommunityReportReceipt> {
    const report: CommunityReportSubmission = {
      schemaVersion: 1,
      reporterProof: this.reporterIdentity.proofForAccount(accountKey),
      reportedAt: new Date().toISOString(),
      ...structuredClone(context),
    };

    if (!this.remoteUrl) {
      const receipt = this.aggregateStore.accept(report);
      this.rebuildEmbeddedFeed();
      return receipt;
    }

    try {
      const data = await fetchJson(`${this.remoteUrl}/api/community/v1/report`, {
        method: "POST",
        body: JSON.stringify(report),
      });
      if (!isReceipt(data)) throw new Error("Community service returned an invalid report receipt.");
      this.outbox.remove(report.reporterProof, report.campaignFingerprint);
      await this.refreshFeed();
      return data;
    } catch {
      this.outbox.enqueue(report);
      return {
        accepted: true,
        duplicate: false,
        queued: true,
        campaignFingerprint: report.campaignFingerprint,
        independentReporters: 1,
        status: "candidate",
        feedUpdated: false,
      };
    }
  }

  /** Central-service ingestion endpoint. Enabled only in explicit server mode. */
  acceptExternalReport(report: CommunityReportSubmission): CommunityReportReceipt {
    if (!this.serverEnabled) throw new Error("Community aggregation service is disabled on this instance.");
    const receipt = this.aggregateStore.accept(report);
    this.rebuildEmbeddedFeed();
    return receipt;
  }

  signedFeed(): SignedCommunityFeed {
    if (!this.serverEnabled) throw new Error("Community aggregation service is disabled on this instance.");
    return this.signer.sign(this.aggregateStore.buildFeedPayload());
  }

  publicInfo(): {
    enabled: boolean;
    keyId: string;
    publicKey: string;
    stats: ReturnType<EncryptedCommunityAggregateStore["stats"]>;
  } {
    return {
      enabled: this.serverEnabled,
      keyId: this.signer.keyId,
      publicKey: this.signer.publicPem,
      stats: this.aggregateStore.stats(),
    };
  }

  async refreshFeed(): Promise<void> {
    if (!this.remoteUrl) {
      this.rebuildEmbeddedFeed();
      return;
    }

    await this.flushOutbox();
    try {
      const document = await fetchJson(`${this.remoteUrl}/api/community/v1/feed`) as SignedCommunityFeed;
      const payload = verifyCommunityFeed(document, this.trustedPublicKeys);
      if (!payload) throw new Error("Community feed signature or freshness validation failed.");
      this.cachedDocument = document;
      this.verifiedEntries = payload.entries;
      writeFileSync(this.feedCachePath, JSON.stringify(document), { mode: 0o600 });
    } catch {
      const cached = this.cachedDocument
        ? verifyCommunityFeed(this.cachedDocument, this.trustedPublicKeys)
        : null;
      this.verifiedEntries = cached?.entries ?? null;
    }
  }

  pendingReports(): number {
    return this.outbox.count();
  }

  private async flushOutbox(): Promise<void> {
    if (!this.remoteUrl) return;
    for (const report of this.outbox.list().slice(0, MAX_FLUSH_PER_REFRESH)) {
      try {
        const data = await fetchJson(`${this.remoteUrl}/api/community/v1/report`, {
          method: "POST",
          body: JSON.stringify(report),
        });
        if (!isReceipt(data)) throw new Error("Invalid community report receipt.");
        this.outbox.remove(report.reporterProof, report.campaignFingerprint);
      } catch {
        break;
      }
    }
  }

  private rebuildEmbeddedFeed(): void {
    const document = this.signer.sign(this.aggregateStore.buildFeedPayload());
    const payload = verifyCommunityFeed(document, [this.signer.publicPem]);
    this.cachedDocument = document;
    this.verifiedEntries = payload?.entries ?? null;
    writeFileSync(this.feedCachePath, JSON.stringify(document), { mode: 0o600 });
  }

  private loadCachedFeed(): void {
    if (!existsSync(this.feedCachePath)) return;
    try {
      const document = JSON.parse(readFileSync(this.feedCachePath, "utf8")) as SignedCommunityFeed;
      const payload = verifyCommunityFeed(document, this.trustedPublicKeys);
      if (payload) {
        this.cachedDocument = document;
        this.verifiedEntries = payload.entries;
      }
    } catch {}
  }
}

export const communityNetwork = new CommunityNetwork();
