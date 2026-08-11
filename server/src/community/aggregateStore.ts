import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  ftruncateSync,
  mkdirSync,
  openSync,
  writeSync,
  writeFileSync,
} from "node:fs";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import { join } from "node:path";
import type { SignedFeedEntry } from "../engine/layers/globalIntelligence.js";
import { readBoundedRegularFile, readBoundedUtf8File, replaceFileFromTemporaryPath } from "../util/localFileIntegrity.js";
import {
  validateStoredCommunityDatabase,
  type StoredCommunityCampaignRecord,
  type StoredCommunityDatabase,
  type StoredCommunityReporterRecord,
} from "./aggregateState.js";
import { CommunityReportCapacityError, CommunityReportRateLimitError, CommunityReportValidationError } from "./errors.js";
import {
  COMMUNITY_STORAGE_KEY_BYTES,
  MAX_COMMUNITY_AGGREGATE_DATABASE_BYTES,
  MAX_COMMUNITY_REPORT_JOURNAL_BYTES,
} from "./resourceLimits.js";
import { COMMUNITY_REPORT_DATABASE_FILE, COMMUNITY_REPORT_JOURNAL_FILE } from "./storageFiles.js";
import type {
  CommunityCampaignStatus,
  CommunityFeedPayload,
  CommunityIndicator,
  CommunityReportReceipt,
  CommunityReportSubmission,
} from "./types.js";

const ALGORITHM = "aes-256-gcm";
const SNAPSHOT_AAD = Buffer.from("email-shield-community-reports-v1", "utf8");
const JOURNAL_AAD = Buffer.from("email-shield-community-report-journal-v1", "utf8");
const MAX_REPORTS_PER_REPORTER_PER_DAY = 50;
const MAX_CAMPAIGNS = 100_000;
const MAX_INDICATORS_PER_REPORT = 32;
const MAX_REPORT_AGE_MS = 30 * 24 * 60 * 60_000;
export const COMMUNITY_REPORT_RETENTION_MS = 90 * 24 * 60 * 60_000;
const MAX_FUTURE_SKEW_MS = 5 * 60_000;
const HUMAN_REPORT_BASE_WEIGHT = 5;
const DEFAULT_SNAPSHOT_INTERVAL = 500;
const REPORT_VERDICTS = new Set(["safe", "unknown", "review", "high_risk", "confirmed_threat"]);
const REPORT_INDICATOR_TYPES = new Set(["sender", "reply_to_domain", "url_domain", "attachment_hash", "campaign"]);
const ENVELOPE_WITHOUT_CIPHERTEXT_BYTES = Buffer.byteLength(JSON.stringify({
  version: 1,
  algorithm: ALGORITHM,
  iv: Buffer.alloc(12).toString("base64"),
  authTag: Buffer.alloc(16).toString("base64"),
  ciphertext: "",
}), "utf8");

interface EncryptedEnvelope {
  version: 1;
  algorithm: "aes-256-gcm";
  iv: string;
  authTag: string;
  ciphertext: string;
}

interface CommunityJournalEvent {
  version: 1;
  acceptedAt: string;
  report: CommunityReportSubmission;
}

interface StorageFingerprint {
  exists: boolean;
  device: number;
  inode: number;
  size: number;
  modifiedMs: number;
  changedMs: number;
}

const MISSING_FINGERPRINT: StorageFingerprint = {
  exists: false,
  device: 0,
  inode: 0,
  size: 0,
  modifiedMs: 0,
  changedMs: 0,
};

function sameFingerprint(left: StorageFingerprint, right: StorageFingerprint): boolean {
  return left.exists === right.exists && left.device === right.device && left.inode === right.inode &&
    left.size === right.size && left.modifiedMs === right.modifiedMs && left.changedMs === right.changedMs;
}

export interface CommunityThresholds {
  warningReporters: number;
  warningWeight: number;
  confirmedReporters: number;
  confirmedStrongReporters: number;
  confirmedWeight: number;
}

export const DEFAULT_COMMUNITY_THRESHOLDS: CommunityThresholds = {
  warningReporters: 3,
  warningWeight: 15,
  confirmedReporters: 5,
  confirmedStrongReporters: 3,
  confirmedWeight: 35,
};

export interface CommunityAggregateStoreOptions {
  now?: () => Date;
  snapshotInterval?: number;
}

function emptyDatabase(): StoredCommunityDatabase {
  return { version: 2, campaigns: {} };
}

function clampScore(value: number): number {
  return Math.max(0, Math.min(20, Number.isFinite(value) ? Math.round(value) : 0));
}

function verdictBonus(verdict: CommunityReportSubmission["verdict"]): number {
  switch (verdict) {
    case "confirmed_threat": return 8;
    case "high_risk": return 5;
    case "review": return 2;
    case "unknown": return 1;
    case "safe": return 0;
  }
}

function reporterWeight(record: Pick<StoredCommunityReporterRecord, "evidenceScore" | "verdict">): number {
  return HUMAN_REPORT_BASE_WEIGHT + clampScore(record.evidenceScore) + verdictBonus(record.verdict);
}

function isStrong(record: StoredCommunityReporterRecord): boolean {
  return record.verdict === "confirmed_threat" || record.verdict === "high_risk" || record.evidenceScore >= 6;
}

function statusFor(record: StoredCommunityCampaignRecord, thresholds: CommunityThresholds): CommunityCampaignStatus {
  const reporters = Object.values(record.reporters);
  const weight = reporters.reduce((sum, item) => sum + reporterWeight(item), 0);
  const strong = reporters.filter(isStrong).length;
  if (
    reporters.length >= thresholds.confirmedReporters &&
    strong >= thresholds.confirmedStrongReporters &&
    weight >= thresholds.confirmedWeight
  ) return "confirmed";
  if (reporters.length >= thresholds.warningReporters && weight >= thresholds.warningWeight) return "warning";
  return "candidate";
}

interface CampaignMetrics {
  reporters: number;
  weight: number;
  strong: number;
}

function metricsFor(record: StoredCommunityCampaignRecord): CampaignMetrics {
  const reporters = Object.values(record.reporters);
  return {
    reporters: reporters.length,
    weight: reporters.reduce((sum, item) => sum + reporterWeight(item), 0),
    strong: reporters.filter(isStrong).length,
  };
}

function statusFromMetrics(metrics: CampaignMetrics, thresholds: CommunityThresholds): CommunityCampaignStatus {
  if (
    metrics.reporters >= thresholds.confirmedReporters &&
    metrics.strong >= thresholds.confirmedStrongReporters &&
    metrics.weight >= thresholds.confirmedWeight
  ) return "confirmed";
  if (metrics.reporters >= thresholds.warningReporters && metrics.weight >= thresholds.warningWeight) return "warning";
  return "candidate";
}

function indicatorKey(indicator: CommunityIndicator): string {
  return `${indicator.type}\0${indicator.value.toLowerCase()}`;
}

function ruleId(campaign: string, indicator: CommunityIndicator): string {
  return `community:${createHash("sha256").update(`${campaign}\0${indicator.type}\0${indicator.value}`).digest("hex").slice(0, 24)}`;
}

function encryptedEnvelopeByteLength(plaintextBytes: number): number {
  return ENVELOPE_WITHOUT_CIPHERTEXT_BYTES + (4 * Math.ceil(plaintextBytes / 3));
}

function validateSubmission(
  input: CommunityReportSubmission,
  nowMs: number,
  enforceSubmissionWindow = true,
): CommunityReportSubmission {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new CommunityReportValidationError("Community report body is invalid.");
  }
  if (input.schemaVersion !== 1) throw new CommunityReportValidationError("Unsupported community report schema.");
  if (typeof input.reporterProof !== "string" || !/^[a-f0-9]{64}$/.test(input.reporterProof)) {
    throw new CommunityReportValidationError("Reporter proof is invalid.");
  }
  if (typeof input.campaignFingerprint !== "string" || !/^[a-f0-9]{64}$/.test(input.campaignFingerprint)) {
    throw new CommunityReportValidationError("Campaign fingerprint is invalid.");
  }
  if (typeof input.reportedAt !== "string" || input.reportedAt.length > 64) {
    throw new CommunityReportValidationError("Report timestamp is invalid.");
  }
  const reportedAt = Date.parse(input.reportedAt);
  if (!Number.isFinite(reportedAt)) throw new CommunityReportValidationError("Report timestamp is invalid.");
  if (enforceSubmissionWindow && (reportedAt > nowMs + MAX_FUTURE_SKEW_MS || reportedAt < nowMs - MAX_REPORT_AGE_MS)) {
    throw new CommunityReportValidationError("Report timestamp is outside the accepted submission window.");
  }
  if (typeof input.verdict !== "string" || !REPORT_VERDICTS.has(input.verdict)) {
    throw new CommunityReportValidationError("Community report verdict is invalid.");
  }
  if (typeof input.evidenceScore !== "number" || !Number.isFinite(input.evidenceScore)) {
    throw new CommunityReportValidationError("Community report evidence score is invalid.");
  }
  if (!Array.isArray(input.evidenceCodes) || input.evidenceCodes.length > 64) {
    throw new CommunityReportValidationError("Community report evidence codes are invalid.");
  }
  if (!input.evidenceCodes.every((code): code is string => typeof code === "string" && /^[A-Z0-9_]{2,80}$/.test(code))) {
    throw new CommunityReportValidationError("Community report evidence codes are invalid.");
  }
  if (!Array.isArray(input.indicators) || input.indicators.length === 0 || input.indicators.length > MAX_INDICATORS_PER_REPORT) {
    throw new CommunityReportValidationError("Community report indicators are invalid.");
  }

  const indicators: CommunityIndicator[] = [];
  const seen = new Set<string>();
  for (const indicator of input.indicators) {
    if (!indicator || typeof indicator !== "object" || Array.isArray(indicator)) {
      throw new CommunityReportValidationError("Community report indicator is invalid.");
    }
    if (typeof indicator.type !== "string" || !REPORT_INDICATOR_TYPES.has(indicator.type) || typeof indicator.value !== "string") {
      throw new CommunityReportValidationError("Community report indicator is invalid.");
    }
    const value = indicator.value.trim().toLowerCase();
    if (!value || value.length > 512) throw new CommunityReportValidationError("Community report indicator is invalid.");
    if (indicator.type === "campaign" && value !== input.campaignFingerprint) {
      throw new CommunityReportValidationError("Community report campaign indicator is inconsistent.");
    }
    const key = `${indicator.type}\0${value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    indicators.push({ type: indicator.type as CommunityIndicator["type"], value });
  }
  if (!indicators.some((item) => item.type === "campaign" && item.value === input.campaignFingerprint)) {
    indicators.unshift({ type: "campaign", value: input.campaignFingerprint });
  }

  return {
    schemaVersion: 1,
    reporterProof: input.reporterProof,
    campaignFingerprint: input.campaignFingerprint,
    reportedAt: new Date(reportedAt).toISOString(),
    verdict: input.verdict,
    evidenceScore: clampScore(input.evidenceScore),
    evidenceCodes: [...new Set(input.evidenceCodes)].sort(),
    indicators,
  };
}

function mergedReporter(
  prior: StoredCommunityReporterRecord | undefined,
  report: CommunityReportSubmission,
  acceptedAt: string,
): StoredCommunityReporterRecord {
  return {
    reportedAt: acceptedAt,
    evidenceScore: Math.max(prior?.evidenceScore ?? 0, report.evidenceScore),
    verdict: reporterWeight({ evidenceScore: report.evidenceScore, verdict: report.verdict }) >=
      reporterWeight(prior ?? { evidenceScore: 0, verdict: "safe" })
      ? report.verdict
      : prior!.verdict,
    evidenceCodes: [...new Set([...(prior?.evidenceCodes ?? []), ...report.evidenceCodes])].sort(),
    indicators: [...new Map(
      [...(prior?.indicators ?? []), ...report.indicators].map((indicator) => [indicatorKey(indicator), indicator]),
    ).values()].sort((left, right) => indicatorKey(left).localeCompare(indicatorKey(right))),
  };
}

function applyReportToDatabase(
  database: StoredCommunityDatabase,
  report: CommunityReportSubmission,
  acceptedAt: string,
): void {
  const campaign = database.campaigns[report.campaignFingerprint];
  const reporter = mergedReporter(campaign?.reporters[report.reporterProof], report, acceptedAt);
  if (campaign) {
    campaign.reporters[report.reporterProof] = reporter;
    if (acceptedAt < campaign.firstSeen) campaign.firstSeen = acceptedAt;
    if (acceptedAt > campaign.lastSeen) campaign.lastSeen = acceptedAt;
  } else {
    database.campaigns[report.campaignFingerprint] = {
      firstSeen: acceptedAt,
      lastSeen: acceptedAt,
      reporters: { [report.reporterProof]: reporter },
    };
  }
}

function reporterEntryBytes(proof: string, reporter: StoredCommunityReporterRecord): number {
  return Buffer.byteLength(`${JSON.stringify(proof)}:${JSON.stringify(reporter)}`, "utf8");
}

function campaignEntryBytes(fingerprint: string, campaign: StoredCommunityCampaignRecord): number {
  return Buffer.byteLength(`${JSON.stringify(fingerprint)}:${JSON.stringify(campaign)}`, "utf8");
}

function pruneExpired(database: StoredCommunityDatabase, nowMs: number): boolean {
  const cutoff = nowMs - COMMUNITY_REPORT_RETENTION_MS;
  let changed = false;
  for (const [fingerprint, campaign] of Object.entries(database.campaigns)) {
    const reporters = Object.fromEntries(Object.entries(campaign.reporters).filter(([, reporter]) => Date.parse(reporter.reportedAt) >= cutoff));
    if (Object.keys(reporters).length === Object.keys(campaign.reporters).length) continue;
    changed = true;
    if (Object.keys(reporters).length === 0) {
      delete database.campaigns[fingerprint];
      continue;
    }
    const timestamps = Object.values(reporters).map((item) => Date.parse(item.reportedAt));
    database.campaigns[fingerprint] = {
      firstSeen: new Date(Math.min(...timestamps)).toISOString(),
      lastSeen: new Date(Math.max(...timestamps)).toISOString(),
      reporters,
    };
  }
  return changed;
}

export class EncryptedCommunityAggregateStore {
  private readonly keyPath: string;
  private readonly databasePath: string;
  private readonly journalPath: string;
  private readonly now: () => Date;
  private readonly snapshotInterval: number;
  private keyCache: Buffer | null = null;
  private databaseCache: StoredCommunityDatabase | null = null;
  private reporterActivity = new Map<string, Map<string, number>>();
  private campaignMetrics = new Map<string, CampaignMetrics>();
  private snapshotPlaintextBytes = 0;
  private nextPruneAt = 0;
  private journalEvents = 0;
  private journalBytes = 0;
  private snapshotFingerprint: StorageFingerprint = MISSING_FINGERPRINT;
  private journalFingerprint: StorageFingerprint = MISSING_FINGERPRINT;

  constructor(
    private readonly dataDirectory: string,
    private readonly thresholds: CommunityThresholds = DEFAULT_COMMUNITY_THRESHOLDS,
    options: CommunityAggregateStoreOptions = {},
  ) {
    this.keyPath = join(dataDirectory, "community-storage.key");
    this.databasePath = join(dataDirectory, COMMUNITY_REPORT_DATABASE_FILE);
    this.journalPath = join(dataDirectory, COMMUNITY_REPORT_JOURNAL_FILE);
    this.now = options.now ?? (() => new Date());
    this.snapshotInterval = Math.max(1, Math.floor(options.snapshotInterval ?? DEFAULT_SNAPSHOT_INTERVAL));
  }

  accept(input: CommunityReportSubmission): CommunityReportReceipt {
    const now = this.now();
    const nowMs = now.getTime();
    const report = validateSubmission(input, nowMs);
    const database = this.loadDatabase(nowMs);
    const needsInitialSnapshot = !existsSync(this.databasePath);
    const existing = database.campaigns[report.campaignFingerprint];
    const activity = this.reporterActivity.get(report.reporterProof);
    const reportsToday = [...(activity?.values() ?? [])].filter((acceptedAt) => acceptedAt >= nowMs - 24 * 60 * 60_000).length;
    const duplicate = Boolean(existing?.reporters[report.reporterProof]);
    if (!duplicate && reportsToday >= MAX_REPORTS_PER_REPORTER_PER_DAY) throw new CommunityReportRateLimitError();
    if (!existing && Object.keys(database.campaigns).length >= MAX_CAMPAIGNS) throw new CommunityReportCapacityError();

    const acceptedAt = now.toISOString();
    const previousMetrics = this.campaignMetrics.get(report.campaignFingerprint) ?? { reporters: 0, weight: 0, strong: 0 };
    const previousStatus = statusFromMetrics(previousMetrics, this.thresholds);
    const priorReporter = existing?.reporters[report.reporterProof];
    const candidateReporter = mergedReporter(priorReporter, report, acceptedAt);
    let candidatePlaintextBytes: number;
    if (existing) {
      const previousEntryBytes = priorReporter ? reporterEntryBytes(report.reporterProof, priorReporter) : 0;
      const nextEntryBytes = reporterEntryBytes(report.reporterProof, candidateReporter);
      candidatePlaintextBytes = this.snapshotPlaintextBytes + nextEntryBytes - previousEntryBytes + (priorReporter ? 0 : 1);
    } else {
      const candidateCampaign: StoredCommunityCampaignRecord = {
        firstSeen: acceptedAt,
        lastSeen: acceptedAt,
        reporters: { [report.reporterProof]: candidateReporter },
      };
      candidatePlaintextBytes = this.snapshotPlaintextBytes + campaignEntryBytes(report.campaignFingerprint, candidateCampaign) +
        (Object.keys(database.campaigns).length > 0 ? 1 : 0);
    }
    this.assertSnapshotCapacityBytes(candidatePlaintextBytes);

    const event: CommunityJournalEvent = { version: 1, acceptedAt, report };
    const line = `${JSON.stringify(this.encryptJson(event, JOURNAL_AAD))}\n`;
    const lineBytes = Buffer.byteLength(line, "utf8");
    if (this.journalBytes + lineBytes > MAX_COMMUNITY_REPORT_JOURNAL_BYTES) this.compact(database);
    if (this.journalBytes + lineBytes > MAX_COMMUNITY_REPORT_JOURNAL_BYTES) throw new CommunityReportCapacityError();
    this.appendJournal(line);

    applyReportToDatabase(database, report, acceptedAt);
    this.databaseCache = database;
    this.snapshotPlaintextBytes = candidatePlaintextBytes;
    const nextMetrics: CampaignMetrics = {
      reporters: previousMetrics.reporters + (priorReporter ? 0 : 1),
      weight: previousMetrics.weight - (priorReporter ? reporterWeight(priorReporter) : 0) + reporterWeight(candidateReporter),
      strong: previousMetrics.strong - (priorReporter && isStrong(priorReporter) ? 1 : 0) + (isStrong(candidateReporter) ? 1 : 0),
    };
    this.campaignMetrics.set(report.campaignFingerprint, nextMetrics);
    const reporterCampaigns = this.reporterActivity.get(report.reporterProof) ?? new Map<string, number>();
    reporterCampaigns.set(report.campaignFingerprint, nowMs);
    this.reporterActivity.set(report.reporterProof, reporterCampaigns);
    this.nextPruneAt = this.nextPruneAt === 0
      ? nowMs + COMMUNITY_REPORT_RETENTION_MS
      : Math.min(this.nextPruneAt, nowMs + COMMUNITY_REPORT_RETENTION_MS);
    this.journalEvents++;
    if (needsInitialSnapshot) {
      this.compact(database);
    } else if (this.journalEvents >= this.snapshotInterval) {
      try { this.compact(database); } catch { /* the accepted report remains durable in the journal */ }
    }

    const status = statusFromMetrics(nextMetrics, this.thresholds);
    return {
      accepted: true,
      duplicate,
      queued: false,
      campaignFingerprint: report.campaignFingerprint,
      independentReporters: nextMetrics.reporters,
      status,
      feedUpdated: status !== previousStatus,
    };
  }

  buildFeedPayload(now = this.now()): CommunityFeedPayload {
    const database = this.loadDatabase(now.getTime());
    const entries: SignedFeedEntry[] = [];
    for (const [fingerprint, campaign] of Object.entries(database.campaigns)) {
      const status = statusFor(campaign, this.thresholds);
      if (status === "candidate") continue;
      const minimumSupport = status === "confirmed" ? this.thresholds.confirmedReporters : this.thresholds.warningReporters;
      const support = new Map<string, { indicator: CommunityIndicator; reporters: Set<string> }>();
      for (const [proof, reporter] of Object.entries(campaign.reporters)) {
        for (const indicator of reporter.indicators) {
          const key = indicatorKey(indicator);
          const item = support.get(key) ?? { indicator, reporters: new Set<string>() };
          item.reporters.add(proof);
          support.set(key, item);
        }
      }
      for (const { indicator, reporters } of support.values()) {
        if (reporters.size < minimumSupport) continue;
        entries.push({
          type: indicator.type,
          value: indicator.value,
          confirmedThreat: status === "confirmed",
          ruleId: ruleId(fingerprint, indicator),
          independentReports: Object.keys(campaign.reporters).length,
          firstSeen: campaign.firstSeen,
          lastSeen: campaign.lastSeen,
        });
      }
    }
    entries.sort((a, b) => `${a.type}:${a.value}:${a.ruleId}`.localeCompare(`${b.type}:${b.value}:${b.ruleId}`));
    return {
      version: 1,
      generatedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 24 * 60 * 60_000).toISOString(),
      entries,
    };
  }

  stats(): { campaigns: number; warnings: number; confirmed: number } {
    const database = this.loadDatabase(this.now().getTime());
    let warnings = 0;
    let confirmed = 0;
    for (const campaign of Object.values(database.campaigns)) {
      const status = statusFor(campaign, this.thresholds);
      if (status === "warning") warnings++;
      if (status === "confirmed") confirmed++;
    }
    return { campaigns: Object.keys(database.campaigns).length, warnings, confirmed };
  }

  private ensureDirectory(): void {
    mkdirSync(this.dataDirectory, { recursive: true, mode: 0o700 });
    try { chmodSync(this.dataDirectory, 0o700); } catch {}
  }

  private readKey(): Buffer {
    if (this.keyCache) return this.keyCache;
    this.ensureDirectory();
    if (!existsSync(this.keyPath)) {
      const generated = randomBytes(COMMUNITY_STORAGE_KEY_BYTES);
      try { writeFileSync(this.keyPath, generated, { mode: 0o600, flag: "wx" }); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
      finally { generated.fill(0); }
    }
    let key: Buffer;
    try {
      key = readBoundedRegularFile(this.keyPath, {
        description: "Community storage encryption key",
        maxBytes: COMMUNITY_STORAGE_KEY_BYTES,
        exactBytes: COMMUNITY_STORAGE_KEY_BYTES,
        requireOwnerOnly: true,
      });
    } catch (error) {
      throw new Error(`Community storage encryption key is invalid: ${error instanceof Error ? error.message : String(error)}`);
    }
    try { chmodSync(this.keyPath, 0o600); } catch {}
    this.keyCache = key;
    return key;
  }

  private encryptJson(value: unknown, aad: Buffer): EncryptedEnvelope {
    const iv = randomBytes(12);
    const cipher = createCipheriv(ALGORITHM, this.readKey(), iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
    return {
      version: 1,
      algorithm: ALGORITHM,
      iv: iv.toString("base64"),
      authTag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64"),
    };
  }

  private decryptJson(envelope: EncryptedEnvelope, aad: Buffer): unknown {
    if (envelope.version !== 1 || envelope.algorithm !== ALGORITHM) throw new Error("Unsupported encrypted community format.");
    const decipher = createDecipheriv(ALGORITHM, this.readKey(), Buffer.from(envelope.iv, "base64"));
    decipher.setAAD(aad);
    decipher.setAuthTag(Buffer.from(envelope.authTag, "base64"));
    return JSON.parse(Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64")),
      decipher.final(),
    ]).toString("utf8"));
  }

  private loadDatabase(nowMs: number): StoredCommunityDatabase {
    if (this.databaseCache) {
      this.assertAuthoritativeStorageUnchanged();
      if (nowMs >= this.nextPruneAt) {
        if (pruneExpired(this.databaseCache, nowMs)) {
          this.rebuildIndexes(this.databaseCache);
          this.compact(this.databaseCache);
        } else {
          this.recomputeNextPruneAt(this.databaseCache);
        }
      }
      return this.databaseCache;
    }
    let database = emptyDatabase();
    if (existsSync(this.databasePath)) {
      try {
        const serialized = readBoundedUtf8File(this.databasePath, {
          description: "Encrypted community report database",
          maxBytes: MAX_COMMUNITY_AGGREGATE_DATABASE_BYTES,
        });
        database = validateStoredCommunityDatabase(
          this.decryptJson(JSON.parse(serialized) as EncryptedEnvelope, SNAPSHOT_AAD),
          MAX_CAMPAIGNS,
        );
      } catch (error) {
        throw new Error(`Encrypted community report database could not be read within the recoverable storage boundary: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    if (existsSync(this.journalPath)) {
      let serialized: string;
      try {
        serialized = readBoundedUtf8File(this.journalPath, {
          description: "Encrypted community report journal",
          maxBytes: MAX_COMMUNITY_REPORT_JOURNAL_BYTES,
          requireOwnerOnly: true,
        });
      } catch (error) {
        throw new Error(`Encrypted community report journal could not be read: ${error instanceof Error ? error.message : String(error)}`);
      }
      this.journalBytes = Buffer.byteLength(serialized, "utf8");
      const complete = serialized.endsWith("\n") ? serialized : serialized.slice(0, serialized.lastIndexOf("\n") + 1);
      const completeBytes = Buffer.byteLength(complete, "utf8");
      if (completeBytes !== this.journalBytes) {
        this.truncateJournalTo(completeBytes, this.journalBytes);
        this.journalBytes = completeBytes;
      }
      for (const line of complete.split("\n")) {
        if (!line) continue;
        try {
          const raw = this.decryptJson(JSON.parse(line) as EncryptedEnvelope, JOURNAL_AAD) as Partial<CommunityJournalEvent>;
          if (raw.version !== 1 || typeof raw.acceptedAt !== "string" || !raw.report) throw new Error("Invalid journal event.");
          const acceptedAtMs = Date.parse(raw.acceptedAt);
          if (!Number.isFinite(acceptedAtMs) || new Date(acceptedAtMs).toISOString() !== raw.acceptedAt) throw new Error("Invalid journal timestamp.");
          const report = validateSubmission(raw.report, acceptedAtMs, false);
          applyReportToDatabase(database, report, raw.acceptedAt);
          this.journalEvents++;
        } catch (error) {
          throw new Error(`Encrypted community report journal is invalid: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
    }
    pruneExpired(database, nowMs);
    validateStoredCommunityDatabase(database, MAX_CAMPAIGNS);
    this.databaseCache = database;
    this.rebuildIndexes(database);
    this.captureAuthoritativeStorageFingerprints();
    return database;
  }

  private rebuildIndexes(database: StoredCommunityDatabase): void {
    this.rebuildReporterActivity(database);
    this.snapshotPlaintextBytes = Buffer.byteLength(JSON.stringify(database), "utf8");
    this.campaignMetrics = new Map(Object.entries(database.campaigns).map(([fingerprint, campaign]) => [fingerprint, metricsFor(campaign)]));
    this.recomputeNextPruneAt(database);
  }

  private recomputeNextPruneAt(database: StoredCommunityDatabase): void {
    let earliest = Number.POSITIVE_INFINITY;
    for (const campaign of Object.values(database.campaigns)) {
      for (const reporter of Object.values(campaign.reporters)) earliest = Math.min(earliest, Date.parse(reporter.reportedAt));
    }
    this.nextPruneAt = Number.isFinite(earliest) ? earliest + COMMUNITY_REPORT_RETENTION_MS : Number.POSITIVE_INFINITY;
  }

  private rebuildReporterActivity(database: StoredCommunityDatabase): void {
    this.reporterActivity.clear();
    for (const [campaign, record] of Object.entries(database.campaigns)) {
      for (const [proof, reporter] of Object.entries(record.reporters)) {
        const campaigns = this.reporterActivity.get(proof) ?? new Map<string, number>();
        campaigns.set(campaign, Date.parse(reporter.reportedAt));
        this.reporterActivity.set(proof, campaigns);
      }
    }
  }

  private assertSnapshotCapacity(database: StoredCommunityDatabase): void {
    const plaintextBytes = Buffer.byteLength(JSON.stringify(database), "utf8");
    this.assertSnapshotCapacityBytes(plaintextBytes);
  }

  private assertSnapshotCapacityBytes(plaintextBytes: number): void {
    if (encryptedEnvelopeByteLength(plaintextBytes) > MAX_COMMUNITY_AGGREGATE_DATABASE_BYTES) throw new CommunityReportCapacityError();
  }

  private appendJournal(line: string): void {
    this.ensureDirectory();
    const noFollow = process.platform === "win32" ? 0 : (fsConstants.O_NOFOLLOW ?? 0);
    const descriptor = openSync(
      this.journalPath,
      fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_CREAT | noFollow,
      0o600,
    );
    const bytes = Buffer.from(line, "utf8");
    try {
      const initial = fstatSync(descriptor);
      if (!initial.isFile() || initial.size !== this.journalBytes || initial.size + bytes.length > MAX_COMMUNITY_REPORT_JOURNAL_BYTES) {
        throw new CommunityReportCapacityError();
      }
      let offset = 0;
      while (offset < bytes.length) offset += writeSync(descriptor, bytes, offset, bytes.length - offset);
      if (fstatSync(descriptor).size !== initial.size + bytes.length) throw new Error("Community report journal changed while being written.");
    } finally {
      bytes.fill(0);
      closeSync(descriptor);
    }
    try { chmodSync(this.journalPath, 0o600); } catch {}
    this.journalBytes += Buffer.byteLength(line, "utf8");
    this.journalFingerprint = this.fileFingerprint(this.journalPath, "Community report journal");
  }

  private compact(database: StoredCommunityDatabase): void {
    this.writeDatabase(database);
    if (existsSync(this.journalPath)) {
      const noFollow = process.platform === "win32" ? 0 : (fsConstants.O_NOFOLLOW ?? 0);
      const descriptor = openSync(this.journalPath, fsConstants.O_WRONLY | fsConstants.O_TRUNC | noFollow);
      try {
        if (!fstatSync(descriptor).isFile()) throw new Error("Community report journal is not a regular file.");
      } finally {
        closeSync(descriptor);
      }
    }
    this.journalEvents = 0;
    this.journalBytes = 0;
    this.captureAuthoritativeStorageFingerprints();
  }

  private truncateJournalTo(size: number, expectedCurrentSize: number): void {
    const noFollow = process.platform === "win32" ? 0 : (fsConstants.O_NOFOLLOW ?? 0);
    const descriptor = openSync(this.journalPath, fsConstants.O_WRONLY | noFollow);
    try {
      const current = fstatSync(descriptor);
      if (!current.isFile() || current.size !== expectedCurrentSize || size < 0 || size > current.size) {
        throw new Error("Community report journal changed while recovering its final record.");
      }
      ftruncateSync(descriptor, size);
    } finally {
      closeSync(descriptor);
    }
  }

  private writeDatabase(database: StoredCommunityDatabase): void {
    this.ensureDirectory();
    this.assertSnapshotCapacity(database);
    const serialized = JSON.stringify(this.encryptJson(database, SNAPSHOT_AAD));
    if (Buffer.byteLength(serialized, "utf8") > MAX_COMMUNITY_AGGREGATE_DATABASE_BYTES) throw new CommunityReportCapacityError();
    const temporaryPath = `${this.databasePath}.${process.pid}.${randomBytes(5).toString("hex")}.tmp`;
    writeFileSync(temporaryPath, serialized, { mode: 0o600 });
    replaceFileFromTemporaryPath(temporaryPath, this.databasePath);
    try { chmodSync(this.databasePath, 0o600); } catch {}
  }

  private fileFingerprint(path: string, description: string): StorageFingerprint {
    if (!existsSync(path)) return MISSING_FINGERPRINT;
    const noFollow = process.platform === "win32" ? 0 : (fsConstants.O_NOFOLLOW ?? 0);
    let descriptor: number;
    try {
      descriptor = openSync(path, fsConstants.O_RDONLY | noFollow);
    } catch {
      throw new Error(`${description} could not be opened safely.`);
    }
    try {
      const state = fstatSync(descriptor);
      if (!state.isFile()) throw new Error(`${description} must be a regular file.`);
      return {
        exists: true,
        device: state.dev,
        inode: state.ino,
        size: state.size,
        modifiedMs: state.mtimeMs,
        changedMs: state.ctimeMs,
      };
    } finally {
      closeSync(descriptor);
    }
  }

  private captureAuthoritativeStorageFingerprints(): void {
    this.snapshotFingerprint = this.fileFingerprint(this.databasePath, "Encrypted community report database");
    this.journalFingerprint = this.fileFingerprint(this.journalPath, "Encrypted community report journal");
  }

  private assertAuthoritativeStorageUnchanged(): void {
    const snapshot = this.fileFingerprint(this.databasePath, "Encrypted community report database");
    const journal = this.fileFingerprint(this.journalPath, "Encrypted community report journal");
    if (!sameFingerprint(snapshot, this.snapshotFingerprint) || !sameFingerprint(journal, this.journalFingerprint)) {
      throw new Error("Encrypted community report storage changed outside the active aggregate writer.");
    }
  }
}
